#!/usr/bin/env python3
"""Step 1: turn a GOG installer (or an existing install folder) into a verified game tree + manifest.

  intake.py extract  <setup_xxx.exe> <out_dir> [--language LANG] [--collisions error|overwrite|rename]
        unpack the installer with scripts/inno.py (pure Python; its setup_xxx-N.bin parts must sit next to
        it; every stored checksum is verified). Collisions default to `error`, so a multi-language installer
        cannot silently overwrite one language's file with another's; on a collision error, list languages
        with `inno.py info <setup.exe>` and rerun with --language. Exit 0 ok, 1 extraction/verification
        error, 2 bad arguments / unsupported installer.
  intake.py verify-hashdb <game_dir>
        check every file listed in GOG's goggame-<id>.hashdb (MD5) - the phase-1 gate.
  intake.py manifest <game_dir> <manifest.json>
        SHA-256 + size of every file (symlinks skipped).
  intake.py compare  <manifest_a.json> <manifest_b.json> [--allow GLOB ...]
        Byte-identity gate between two trees (e.g. a fresh extraction vs the reference manifest a project
        committed, or vs an installed copy). Paths are compared case-insensitively. A file present on
        only one side FAILS the gate unless it matches an --allow glob (fnmatch, case-insensitive, tried
        against the relative path and the basename; repeatable), e.g. --allow 'unins000.*' for the
        uninstaller a real install adds, or saves/configs written after first run. Allowed files are listed
        under "allowed_only_in_a/b". Prints JSON then PASS/FAIL. Exit 0 = PASS (no differing common file and
        no unallowed one-sided file), 1 = FAIL, 2 = unreadable manifest.

inno.py writes the game to <out_dir>/ for GOG Galaxy-era installers (<out_dir>/app/ for older ones), next to
installer-only folders such as __redist/ and commonappdata/; extract prints which folder holds the game and
which folders to leave out (or --allow) when comparing with an install. Galaxy-era installers can also have game
files as plain {app} entries (inno.py: app/x): extract moves those the game's goggame-*.hashdb lists into the game
folder, where a real install puts them. Run with python3 -I. Stdlib only.
"""
import fnmatch, glob, hashlib, json, os, subprocess, sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def manifest(root):
    if not os.path.isdir(root):
        sys.exit(f'not a directory: {root}')
    files = {}
    for r, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(r, f)
            if os.path.islink(p):
                continue
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            files[rel] = {'size': os.path.getsize(p), 'sha256': sha256(p)}
    return {'root_name': os.path.basename(os.path.abspath(root)), 'files': dict(sorted(files.items()))}


HERE = os.path.dirname(os.path.abspath(__file__))


def extract(installer, out, language=None, collisions='error'):
    """Unpack with the skill's pure-Python Inno Setup reader (scripts/inno.py): no external tools."""
    if not os.path.isfile(installer):
        print(f'installer not found: {installer}', file=sys.stderr)
        return 2
    stem = os.path.splitext(installer)[0]
    parts = sorted(glob.glob(glob.escape(stem) + '-*.bin'))
    print('installer:', installer, '(%d MB)' % (os.path.getsize(installer) >> 20))
    print('parts    :', ', '.join(os.path.basename(p) for p in parts) if parts else 'none (single-file installer)')
    inno = [sys.executable, '-I', os.path.join(HERE, 'inno.py')]
    info = subprocess.run(inno + ['info', installer], capture_output=True, text=True)
    print((info.stdout + info.stderr).strip()[-1500:])
    if info.returncode:
        print(hint(info.stdout + info.stderr, info.returncode), file=sys.stderr)
        return info.returncode
    os.makedirs(out, exist_ok=True)
    cmd = inno + ['extract', installer, out, '--collisions', collisions, '--quiet']
    if language:
        cmd += ['--language', language]
    print('running  : inno.py extract' + (f' --language {language}' if language else ''))
    p = subprocess.run(cmd, capture_output=True, text=True)
    print((p.stdout + p.stderr).strip()[-2000:])
    if p.returncode:
        print(hint(p.stdout + p.stderr, p.returncode), file=sys.stderr)
        return p.returncode
    moved = install_app_files(out)
    if moved:
        print('installed from app/ into the game folder (GOG hashdb lists them; a real install puts {app} files '
              'there): %d file(s): %s' % (len(moved), ', '.join(moved)))
    print('game folder:', game_folder(out))
    return 0


def hashdb_listed(game_dir):
    """{lowercase path: path} of every file a goggame-*.hashdb in game_dir lists, or {} without one."""
    import zipfile, struct
    out = {}
    for db in sorted(glob.glob(os.path.join(glob.escape(game_dir), 'goggame-*.hashdb'))):
        try:
            z = zipfile.ZipFile(db)
            data = z.read(z.infolist()[0])
            hsize, version, count = struct.unpack_from('<III', data, 0)
        except (OSError, zipfile.BadZipFile, struct.error, IndexError):
            continue
        if hsize != 12 or len(data) != 12 + count * 1056:
            continue
        for i in range(count):
            path = data[12 + i * 1056:12 + i * 1056 + 1024].split(b'\0', 1)[0].decode('utf-8').replace('\\', '/')
            out.setdefault(path.lower(), path)
    return out


def install_app_files(out):
    """GOG Galaxy-era installers write their split files to <out>/ but plain {app} entries to <out>/app/ (inno.py keeps
    the constant as a folder, like innoextract). A real install puts both in the same folder, so an app/ file that
    the game's own goggame-*.hashdb lists, and that is not already in <out>/, is moved there (under the hashdb's
    spelling of the path). Everything else in app/ (goggame-<id>.ico, webcache.zip, [Dirs]) stays installer-only."""
    app = os.path.join(out, 'app')
    listed = hashdb_listed(out) if os.path.isdir(app) else {}
    moved = []
    for r_, ds, fs in sorted(os.walk(app)) if listed else []:
        for f in sorted(fs):
            src = os.path.join(r_, f)
            rel = os.path.relpath(src, app).replace(os.sep, '/')
            want = listed.get(rel.lower())
            if not want:
                continue
            dst = os.path.join(out, *want.split('/'))
            if os.path.lexists(dst):
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(src, dst)
            moved.append(want)
    return sorted(moved)


INSTALLER_ONLY = {'__redist', 'commonappdata', 'tmp', '{tmp}', 'userappdata', 'userdocs', 'sys', 'win'}


def game_folder(out):
    """inno.py puts the game in <out>/ for GOG Galaxy-era installers and in <out>/app/ for older ones; pick the one that
    holds more files, ignoring installer-only folders."""
    def score(d):
        n = 0
        for e in os.listdir(d):
            if e.lower() in INSTALLER_ONLY or (d == out and e == 'app'):
                continue
            p = os.path.join(d, e)
            n += sum(len(fs) for _, _, fs in os.walk(p)) if os.path.isdir(p) else 1
        return n
    app = os.path.join(out, 'app')
    best = app if os.path.isdir(app) and score(app) > score(out) else out
    extra = sorted(e + '/' for e in os.listdir(out) if os.path.isdir(os.path.join(out, e))
                   and (e.lower() in INSTALLER_ONLY or (best == out and e == 'app')))
    return best + ('  (installer-only, not part of the game tree: %s)' % ' '.join(extra) if extra else '')


def hint(text, rc):
    t = text.lower()
    if 'rar' in t:
        return ('The .bin parts are RAR archives (older multi-part GOG installers). They are not supported: copy an '
                'installed copy of the game instead and continue with verify-hashdb / manifest on that folder.')
    if 'collision' in t:
        return ('Two installer entries map to the same output path (usually per-language copies). List languages '
                'with `inno.py info <setup.exe>` and rerun with --language LANG, or pass --collisions rename.')
    if 'unsupported' in t or rc == 2:
        return ('inno.py does not support this installer (version, encryption or not Inno Setup; see its message). '
                'Use an installed copy of the game instead (references/intake.md).')
    return 'inno.py failed (exit %d): a checksum/CRC/data error - corrupt download or a missing .bin part?' % rc


def compare(a, b, allow=()):
    try:
        A, B = json.load(open(a))['files'], json.load(open(b))['files']
    except (OSError, ValueError, KeyError) as e:
        print(f'cannot read manifest: {e}', file=sys.stderr)
        return 2
    fold = lambda d: {k.lower(): (k, v) for k, v in d.items()}
    FA, FB = fold(A), fold(B)
    pats = [g.lower() for g in allow]
    allowed = lambda p: any(fnmatch.fnmatchcase(p.lower(), g) or fnmatch.fnmatchcase(p.lower().rsplit('/', 1)[-1], g)
                            for g in pats)
    only_a = sorted(FA[k][0] for k in FA.keys() - FB.keys())
    only_b = sorted(FB[k][0] for k in FB.keys() - FA.keys())
    diff = sorted(FA[k][0] for k in FA.keys() & FB.keys() if FA[k][1]['sha256'] != FB[k][1]['sha256'])
    same = len(FA.keys() & FB.keys()) - len(diff)
    res = {'identical': same, 'different': diff,
           'only_in_a': [p for p in only_a if not allowed(p)], 'only_in_b': [p for p in only_b if not allowed(p)],
           'allowed_only_in_a': [p for p in only_a if allowed(p)], 'allowed_only_in_b': [p for p in only_b if allowed(p)],
           'allow': list(allow)}
    print(json.dumps(res, indent=1))
    ok = not diff and not res['only_in_a'] and not res['only_in_b']
    why = []
    if diff:
        why.append(f'{len(diff)} common file(s) differ')
    if res['only_in_a'] or res['only_in_b']:
        why.append(f'{len(res["only_in_a"])} file(s) only in A, {len(res["only_in_b"])} only in B '
                   '(not matched by --allow)')
    print('PASS' if ok else 'FAIL: ' + '; '.join(why))
    return 0 if ok else 1


def verify_hashdb(game_dir):
    """GOG ships goggame-<id>.hashdb in the game folder: a ZIP holding one file with a 12-byte header
    (uint32 header_size=12, version=1, count) and count records of path[1024] (UTF-8, NUL-padded) +
    md5_hex[32]. Check every listed file's MD5 - an independent gate from GOG itself."""
    import zipfile, struct
    dbs = sorted(glob.glob(os.path.join(glob.escape(game_dir), 'goggame-*.hashdb')))
    if not dbs:
        print(f'no goggame-*.hashdb in {game_dir} (not a GOG Galaxy-era game?): use `compare` against a '
              'reference manifest instead', file=sys.stderr)
        return 2
    rc = 0
    for db in dbs:
        z = zipfile.ZipFile(db)
        data = z.read(z.infolist()[0])
        hsize, version, count = struct.unpack_from('<III', data, 0)
        if hsize != 12 or len(data) != 12 + count * 1056:
            print(f'{os.path.basename(db)}: unknown hashdb layout (header {hsize}, version {version}, '
                  f'{len(data)} bytes for {count} records)', file=sys.stderr)
            return 2
        listed, ok, bad, missing = set(), 0, [], []
        for i in range(count):
            r = data[12 + i * 1056:12 + (i + 1) * 1056]
            path = r[:1024].split(b'\0', 1)[0].decode('utf-8').replace('\\', '/')
            md5 = r[1024:].decode('ascii')
            listed.add(path.lower())
            p = os.path.join(game_dir, *path.split('/'))
            if not os.path.isfile(p):
                missing.append(path); continue
            h = hashlib.md5()
            with open(p, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
            (bad.append(path) if h.hexdigest() != md5 else None)
            ok += h.hexdigest() == md5
        unlisted = []
        for r_, _, fs in os.walk(game_dir):
            for f in fs:
                rel = os.path.relpath(os.path.join(r_, f), game_dir).replace(os.sep, '/')
                if rel.lower() not in listed and not f.lower().startswith('goggame-'):
                    unlisted.append(rel)
        print(json.dumps({'hashdb': os.path.basename(db), 'version': version, 'records': count, 'md5_ok': ok,
                          'md5_mismatch': bad, 'missing': missing,
                          'not_listed (excluding goggame-*)': sorted(unlisted)}, indent=1))
        if bad or missing:
            rc = 1
    print('PASS' if rc == 0 else 'FAIL')
    return rc


def opt(args, name, default=None, multi=False):
    vals, rest, i = [], [], 0
    while i < len(args):
        if args[i] == name:
            if i + 1 >= len(args):
                sys.exit(f'{name} needs a value')
            vals.append(args[i + 1]); i += 2
        elif args[i].startswith(name + '='):
            vals.append(args[i].split('=', 1)[1]); i += 1
        else:
            rest.append(args[i]); i += 1
    args[:] = rest
    return vals if multi else (vals[-1] if vals else default)


if __name__ == '__main__':
    argv = sys.argv[1:]
    if len(argv) < 2 or argv[0] in ('-h', '--help'):
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    cmd = argv.pop(0)
    if cmd == 'extract':
        lang = opt(argv, '--language')
        coll = opt(argv, '--collisions', 'error')
        if coll not in ('error', 'overwrite', 'rename') or len(argv) != 2:
            print(__doc__, file=sys.stderr)
            sys.exit(2)
        sys.exit(extract(argv[0], argv[1], lang, coll))
    elif cmd == 'verify-hashdb' and len(argv) == 1:
        sys.exit(verify_hashdb(argv[0]))
    elif cmd == 'manifest' and len(argv) == 2:
        m = manifest(argv[0])
        json.dump(m, open(argv[1], 'w'), indent=1)
        print(len(m['files']), 'files ->', argv[1])
    elif cmd == 'compare':
        allow = opt(argv, '--allow', multi=True)
        if len(argv) != 2:
            print(__doc__, file=sys.stderr)
            sys.exit(2)
        sys.exit(compare(argv[0], argv[1], allow))
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
