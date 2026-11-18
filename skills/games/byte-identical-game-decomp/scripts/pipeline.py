#!/usr/bin/env python3
"""Run the skill's phases on a project folder from one config file, decomp.json (references/pipeline.md).

  pipeline.py [--project DIR] <command> [options]

  init --game NAME [--force]          decomp.json skeleton (PE binaries found in the game folder listed),
                                      .gitignore lines for game-derived folders, the project folders
  intake <setup.exe | installed dir> [--language L] [--force]
                                      phase 1: extract (scripts/intake.py) into <work>/installer, copy the game
                                      folder to paths.game, GOG hashdb gate, SHA-256 manifest: written to
                                      paths.manifest, or compared with it when it already exists
  inventory                           phase 2: scripts/inventory.py census -> <reports>/inventory.json; files no
                                      magic matched must be handled by a configured module or be a binary
  archives [--force]                  extract the configured archives -> <extracted>/<archive>/ + _members.json
  decode [--module M] [--jobs N]      phase 3: scripts/verify.py for every (module, tree) ->
                                      <reports>/<tree>/<module>.json, decoded/<module>/; then the completeness gate
  completeness                        the phase-3 gate alone (also run by decode) -> <reports>/completeness.json
  recover [--binary B] [--force]      phase 4: ghidra/run_recovery.sh + code_coverage_check.py per binary
  features [--binary B] [--force]     phase 5 input: build_features.py -> <analysis>/<B>/
  names [--binary B]                  phase 5: ghidra/apply_names.sh with <analysis>/<B>/names_apply.json -> named
  reassemble [--binary B] [--split] [--force] [--cache]
                                      phase 5b: split to text (when missing, or --split), rebuild, SHA-256 gate
                                      -> <reports>/reassemble/<B>.json
  skeleton [--binary B] [--force]     phase 6 setup: phase6_skeleton.py -> <src>/<B>/ (matching binaries)
  match [--binary B] [--units u1,u2] [--jobs N]
                                      phase 6: compile every unit (msvc.sh) and compare (objcmp.py report);
                                      objects in <build>/obj/<B>/, status -> <reports>/match/<B>.json
  build [--mode source|identical] [--out DIR] [--no-original] [--skip-data] [--jobs N] [--run]
                                      every file of the game from the editable forms (see build())
  verify [--out DIR]                  SHA-256 of every built file against the game folder -> <reports>/verify.json
  status                              one table: every phase, its gate, read from the files on disk

Each command prints progress to stderr and a JSON summary to stdout, and exits 0 only when its gate holds
(1 gate failed, 2 bad arguments or config). Nothing here is game-specific: names, paths, archives, format
modules, binaries, compiler and run settings all come from decomp.json; paths may be absolute.
Python stdlib + Ghidra + the user's compiler under Wine (phase 6) only. Run with python3 -I.
"""
import argparse, concurrent.futures as cf, glob, hashlib, importlib.util, json, os, re, shutil, subprocess, sys
import tempfile, time, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PY = [sys.executable, '-I']
DEFAULT_PATHS = {'game': 'work/game', 'extracted': 'extracted', 'decoded': 'decoded', 'reports': 'reports',
                 'formats': 'tools/formats', 'analysis': 'analysis', 'src': 'src_matched', 'build': 'build',
                 'work': 'work', 'manifest': 'manifests/game.json'}
GITIGNORE = ['# Game-derived content (copyrighted; regenerate locally from your own installer)', '/extracted/',
             '/decoded/', '/previews/', '/decompiled*/', '/reassembled/', '/src_matched/', '/analysis/', '/work/',
             '/build/', '__pycache__/', '*.pyc', '.DS_Store']
SIGS = {b'PK\x03\x04': 'zip', b'OggS': 'ogg', b'RIFF': 'riff', b'\x89PNG\r\n\x1a\n': 'png'}
MEMBERS_JSON = '_members.json'                 # written by `archives` into the extracted tree
LINE = re.compile(r'^(OK|DIFF|STUB|UNMAPPED|AMBIGUOUS|ERROR)\s+0x([0-9a-f]+)\s+(\S+)\s+(\d+|-)', re.M)
SUM = re.compile(r'functions identical: (\d+)/(\d+).*?stubs (\d+); bytes identical: (\d+)/(\d+)')
NONMATCH = re.compile(r'^// FUNCTION: \S+ (0x[0-9a-fA-F]+)\s*\n// NONMATCHING', re.M)


class ConfigError(Exception):
    pass


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def walk_files(root):
    """Relative paths ('/'-separated) of every file under root, sorted."""
    out = []
    for r, ds, fs in os.walk(root):
        ds.sort()
        out += [os.path.relpath(os.path.join(r, f), root).replace(os.sep, '/') for f in sorted(fs)]
    return out


# ------------------------------------------------------------------------------------------------- config
class Project:
    def __init__(self, root, need_config=True):
        self.root = os.path.abspath(root)
        self.cfg_path = os.path.join(self.root, 'decomp.json')
        if os.path.exists(self.cfg_path):
            try:
                self.cfg = json.load(open(self.cfg_path, encoding='utf-8'))
            except ValueError as e:
                raise ConfigError(f'decomp.json: {e}')
        elif need_config:
            raise ConfigError(f'no decomp.json in {self.root} (run `pipeline.py init --game NAME` first)')
        else:
            self.cfg = {}
        paths = dict(DEFAULT_PATHS, **self.cfg.get('paths', {}))
        self.p = {k: self.abs(v) for k, v in paths.items()}

    def abs(self, p):
        return os.path.normpath(os.path.join(self.root, os.path.expanduser(p)))

    def rel(self, p):
        """Project-relative form for printing and for tool arguments (cwd = project)."""
        r = os.path.relpath(p, self.root)
        return p if r == '..' or r.startswith('..' + os.sep) else r

    def report(self, *parts):
        return os.path.join(self.p['reports'], *parts)

    # formats: [{"module", "trees": [...]}] in build order
    def formats(self):
        out = []
        for f in self.cfg.get('formats', []):
            if isinstance(f, str):
                f = {'module': f, 'trees': ['game']}
            if 'module' not in f:
                raise ConfigError(f'formats entry without "module": {f}')
            trees = f.get('trees', ['game'])
            for t in trees:
                if t not in ('game', 'extracted'):
                    raise ConfigError(f'format {f["module"]}: unknown tree {t!r} (game or extracted)')
            out.append(dict(f, trees=trees))
        return out

    def binaries(self, name=None, matching_only=False):
        out = []
        for b in self.cfg.get('binaries', []):
            if 'file' not in b:
                raise ConfigError(f'binaries entry without "file": {b}')
            stem = os.path.splitext(os.path.basename(b['file']))[0]
            nm = b.get('name', stem)
            low = stem.lower()
            r = dict(name=nm, file=b['file'], stem=stem, matching=bool(b.get('matching', False)),
                     binary=os.path.join(self.p['game'], b['file']),
                     decompiled=self.abs(b.get('decompiled', f'decompiled_{low}')),
                     named=self.abs(b.get('named', f'decompiled_named_{low}')),
                     reassembled=self.abs(b.get('reassembled', f'reassembled/{nm}')),
                     src=self.abs(b['src']) if 'src' in b else os.path.join(self.p['src'], nm),
                     analysis=self.abs(b['analysis']) if 'analysis' in b else os.path.join(self.p['analysis'], nm),
                     project=self.abs(b['ghidra_project']) if 'ghidra_project' in b
                     else os.path.join(self.p['work'], f'ghidra_{stem}'))
            out.append(r)
        if name:
            out = [b for b in out if name in (b['name'], b['file'], b['stem'])]
            if not out:
                raise ConfigError(f'no binary {name!r} in decomp.json')
        if matching_only:
            out = [b for b in out if b['matching']]
        return out

    def toolchain_env(self):
        tc = self.cfg.get('toolchain', {})
        env = dict(os.environ)
        if tc.get('wineprefix'):
            env.setdefault('MSVC_PREFIX', os.path.expanduser(tc['wineprefix']))
        if tc.get('vs'):
            env.setdefault('MSVC_VS', tc['vs'])
        if tc.get('sdk'):
            env.setdefault('MSVC_SDK', tc['sdk'])
        return env

    def libdirs(self):
        tc = self.cfg.get('toolchain', {})
        prefix = os.path.expanduser(tc.get('wineprefix', '~/.wine'))
        libs = tc.get('sdk_lib', [])
        libs = [libs] if isinstance(libs, str) else libs
        return [l if os.path.isabs(os.path.expanduser(l)) else os.path.join(prefix, 'drive_c', l) for l in libs]


def run(cmd, proj, env=None, capture=False, cwd=None):
    """Run a tool with cwd = the project; its stdout goes to our stderr (stdout carries the JSON summary)."""
    log('+', ' '.join(str(c) for c in cmd[:7]) + (' ...' if len(cmd) > 7 else ''))
    if capture:
        return subprocess.run(cmd, cwd=cwd or proj.root, env=env, capture_output=True, text=True, errors='replace')
    return subprocess.run(cmd, cwd=cwd or proj.root, env=env, stdout=sys.stderr)


def load_format(formats_dir, name):
    if formats_dir not in sys.path:
        sys.path.insert(0, formats_dir)        # helpers (pngio, fmt_<name>_*.py) import by name
    path = os.path.join(formats_dir, f'fmt_{name}.py')
    if not os.path.exists(path):
        raise ConfigError(f'format module not found: {path}')
    spec = importlib.util.spec_from_file_location(f'fmt_{name}', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------------------------------- init
def cmd_init(proj, a):
    if os.path.exists(proj.cfg_path) and not a.force:
        raise ConfigError('decomp.json exists (use --force to overwrite)')
    game = proj.p['game']
    binaries = []
    if os.path.isdir(game):
        for rel in walk_files(game):
            p = os.path.join(game, rel)
            if os.path.splitext(rel)[1].lower() in ('.exe', '.dll', '.asi', '.flt', '.drv') and \
                    open(p, 'rb').read(2) == b'MZ':
                stem = os.path.splitext(os.path.basename(rel))[0]
                binaries.append({'name': stem, 'file': rel, 'decompiled': f'decompiled_{stem.lower()}',
                                 'named': f'decompiled_named_{stem.lower()}', 'reassembled': f'reassembled/{stem}',
                                 'matching': False})
    cfg = {'game': a.game, 'paths': {k: v for k, v in DEFAULT_PATHS.items()}, 'archives': [], 'formats': [],
           'containers': [], 'binaries': binaries,
           'toolchain': {'compiler': 'msvc', 'version': '', 'flags': '/O2', 'wineprefix': '~/.wine-msvc',
                         'sdk_lib': []},
           'run': {'wineprefix': '~/.wine',
                   'exe': next((x['file'] for x in binaries if x['file'].lower().endswith('.exe')), '')}}
    os.makedirs(proj.root, exist_ok=True)
    json.dump(cfg, open(proj.cfg_path, 'w'), indent=1)
    gi = os.path.join(proj.root, '.gitignore')
    have = open(gi).read().splitlines() if os.path.exists(gi) else []
    add = [l for l in GITIGNORE if l not in have]
    if add:
        with open(gi, 'a') as f:
            f.write(('\n' if have and have[-1] != '' else '') + '\n'.join(add) + '\n')
    for k in ('formats', 'reports', 'build', 'work'):
        os.makedirs(proj.p[k], exist_ok=True)
    os.makedirs(os.path.dirname(proj.p['manifest']), exist_ok=True)
    return True, dict(command='init', config='decomp.json', binaries=[b['file'] for b in binaries],
                      gitignore_added=add, next='fill in archives/formats/containers/toolchain/run, then intake')


# ------------------------------------------------------------------------------------------------- intake
def cmd_intake(proj, a):
    sys.path.insert(0, HERE)
    import intake
    game = proj.p['game']
    if os.path.isdir(game) and os.listdir(game) and not a.force:
        raise ConfigError(f'{proj.rel(game)} is not empty (use --force to replace it)')
    src = os.path.abspath(a.installer)
    if os.path.isdir(src):
        folder, how = src, 'installed folder'
    else:
        inst = os.path.join(proj.p['work'], 'installer')
        if os.path.isdir(inst):
            shutil.rmtree(inst)
        cmd = PY + [os.path.join(HERE, 'intake.py'), 'extract', src, inst] + \
            (['--language', a.language] if a.language else [])
        if run(cmd, proj).returncode:
            return False, dict(command='intake', error='extraction failed (see the log above)')
        folder, how = intake.game_folder(inst).split('  (', 1)[0], 'installer'
    if os.path.isdir(game):
        shutil.rmtree(game)
    skip = lambda d, names: [n for n in names if os.path.isdir(os.path.join(d, n)) and d == folder and
                             (n.lower() in intake.INSTALLER_ONLY or (n == 'app' and how == 'installer'))]
    shutil.copytree(folder, game, ignore=skip, symlinks=True)
    log(f'game folder: {proj.rel(game)} ({len(walk_files(game))} files, from the {how})')
    hp = run(PY + [os.path.join(HERE, 'intake.py'), 'verify-hashdb', game], proj, capture=True)
    log(hp.stdout + hp.stderr)
    m = intake.manifest(game)
    res = dict(command='intake', source=how, game=proj.rel(game), files=len(m['files']),
               hashdb={0: 'PASS', 1: 'FAIL', 2: 'no goggame-*.hashdb'}.get(hp.returncode, hp.returncode))
    man = proj.p['manifest']
    if os.path.exists(man):
        tmp = os.path.join(proj.p['build'], 'work', 'manifest_intake.json')
        os.makedirs(os.path.dirname(tmp), exist_ok=True)
        json.dump(m, open(tmp, 'w'), indent=1)
        cp = run(PY + [os.path.join(HERE, 'intake.py'), 'compare', tmp, man], proj, capture=True)
        log(cp.stdout)
        res['manifest'] = dict(path=proj.rel(man), compared='PASS' if cp.returncode == 0 else 'FAIL')
        man_ok = cp.returncode == 0
    else:
        os.makedirs(os.path.dirname(man), exist_ok=True)
        json.dump(m, open(man, 'w'), indent=1)
        res['manifest'] = dict(path=proj.rel(man), written=True)
        man_ok = True
    ok = man_ok and (hp.returncode == 0 or (hp.returncode == 2 and 'compared' in res['manifest']))
    os.makedirs(proj.p['reports'], exist_ok=True)
    json.dump(dict(res, ok=ok), open(proj.report('intake.json'), 'w'), indent=1)
    return ok, res


# ---------------------------------------------------------------------------------------------- inventory
def module_exts(proj):
    out = {}
    for f in proj.formats():
        try:
            for e in load_format(proj.p['formats'], f['module']).EXTS:
                out.setdefault(e.lower(), []).append(f['module'])
        except ConfigError:
            pass
    return out


def inventory_gate(proj, inv):
    exts = module_exts(proj)
    bins = {b['file'].lower().replace('\\', '/') for b in proj.binaries()}
    unexplained = [p for p in inv.get('unclassified', [])
                   if os.path.splitext(p)[1].lower() not in exts and p.lower().replace('\\', '/') not in bins]
    return unexplained


def cmd_inventory(proj, a):
    out = proj.report('inventory.json')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    p = run(PY + [os.path.join(HERE, 'inventory.py'), proj.p['game'], '--json', out], proj)
    if p.returncode or not os.path.exists(out):
        return False, dict(command='inventory', error='inventory.py failed')
    inv = json.load(open(out))
    unexplained = inventory_gate(proj, inv)
    found = sorted(x['path'] for x in inv.get('archives', []))
    conf = proj.cfg.get('archives', [])
    res = dict(command='inventory', report=proj.rel(out), files=len(inv['files']),
               unclassified=len(inv.get('unclassified', [])), unexplained=unexplained,
               zip_archives_found=found, archives_not_configured=[x for x in found if x not in conf])
    return not unexplained, res


# ----------------------------------------------------------------------------------------------- archives
def safe_rel(name):
    parts = name.replace('\\', '/').split('/')
    if name.startswith('/') or any(p in ('..',) for p in parts) or ':' in parts[0]:
        raise ValueError(f'unsafe member path: {name!r}')
    return os.path.join(*[p for p in parts if p])


def cmd_archives(proj, a):
    out = proj.p['extracted']
    report, counts = {}, {}
    for arc in proj.cfg.get('archives', []):
        base = os.path.join(out, arc)
        if os.path.isdir(base) and os.listdir(base):
            if not a.force:
                raise ConfigError(f'{proj.rel(base)} exists (use --force to extract again)')
            shutil.rmtree(base)
        z = zipfile.ZipFile(os.path.join(proj.p['game'], arc))
        names = [i.filename for i in z.infolist()]
        if len(set(names)) != len(names):
            raise ValueError(f'{arc}: duplicate member names')
        members = {}
        for i in z.infolist():
            rel = safe_rel(i.filename)
            if i.is_dir():
                os.makedirs(os.path.join(base, rel), exist_ok=True)
                continue
            data = z.read(i)                      # raises on CRC mismatch
            dst = os.path.join(base, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, 'wb') as f:
                f.write(data)
            members[i.filename] = dict(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        report[arc] = members
        counts[arc] = len(members)
        log(f'{arc}: {len(members)} files')
    os.makedirs(out, exist_ok=True)
    json.dump(report, open(os.path.join(out, MEMBERS_JSON), 'w'), indent=1)
    return True, dict(command='archives', out=proj.rel(out), members=counts, total=sum(counts.values()))


# ------------------------------------------------------------------------------------------------- decode
def tree_root(proj, tree):
    return proj.p['game'] if tree == 'game' else proj.p['extracted']


def cmd_decode(proj, a):
    jobs = []
    for f in proj.formats():
        if a.module and f['module'] != a.module:
            continue
        for t in f['trees']:
            jobs.append((f['module'], t))
    if a.module and not jobs:
        raise ConfigError(f'no format module {a.module!r} in decomp.json')

    def one(job):
        m, t = job
        rep = proj.report(t)
        p = run(PY + [os.path.join(HERE, 'verify.py'), m, '--src', tree_root(proj, t), '--formats-dir',
                      proj.p['formats'], '--out', proj.p['decoded'], '--report', rep], proj, capture=True)
        log(f'[{t}/{m}] exit {p.returncode}\n' + (p.stdout + p.stderr)[-1500:])
        r = os.path.join(rep, f'{m}.json')
        d = json.load(open(r)) if os.path.exists(r) else {}
        return dict(module=m, tree=t, files=d.get('files', 0), passed=d.get('passed', 0), failed=d.get('failed'),
                    opaque_bytes=d.get('opaque_bytes'), seconds=d.get('seconds'), ok=p.returncode == 0)
    t0 = time.time()
    with cf.ThreadPoolExecutor(max(1, a.jobs)) as ex:
        rows = list(ex.map(one, jobs))
    gate_ok, comp = completeness(proj)
    res = dict(command='decode', modules=rows, seconds=round(time.time() - t0),
               completeness={k: comp[k] for k in ('files_seen', 'ok', 'out_of_scope', 'problems',
                                                  'unexpected_nested_signatures', 'opaque_bytes', 'bytes_ok')})
    return all(r['ok'] for r in rows) and gate_ok, res


def completeness(proj, write=True):
    """Phase-3 gate without a routing table: a file is covered when exactly one module's report
    (<reports>/<tree>/<module>.json) lists it, ok, with the SHA-256 it has now; binaries are out of scope;
    no embedded container signature away from offset 0 except in configured containers (and binaries,
    whose hits are code constants and strings: listed, phase 4 covers them)."""
    trees = {'game': proj.p['game']}
    if os.path.isdir(proj.p['extracted']):
        trees['extracted'] = proj.p['extracted']
    listed = {}                      # (tree, rel) -> [(module, entry)]
    missing_reports = []
    for f in proj.formats():
        for t in f['trees']:
            rp = proj.report(t, f'{f["module"]}.json')
            if not os.path.exists(rp):
                missing_reports.append(f'{t}/{f["module"]}.json')
                continue
            for e in json.load(open(rp))['per_file']:
                listed.setdefault((t, e['file'].replace(os.sep, '/')), []).append((f'{t}/{f["module"]}', e))
    bins = {b['file'].replace('\\', '/').lower() for b in proj.binaries()}
    containers = set(proj.cfg.get('containers', []))
    rows, problems, nested, nested_bin, seen = [], [], [], [], set()
    problems += [dict(report=r, problem='report missing (run decode)') for r in missing_reports]
    for tree, root in trees.items():
        if not os.path.isdir(root):
            problems.append(dict(tree=tree, problem=f'folder missing: {proj.rel(root)}'))
            continue
        for rel in walk_files(root):
            if tree == 'extracted' and rel == MEMBERS_JSON:
                continue
            seen.add((tree, rel))
            data = open(os.path.join(root, rel), 'rb').read()
            sha = hashlib.sha256(data).hexdigest()
            is_bin = tree == 'game' and rel.lower() in bins
            if os.path.basename(rel) not in containers and rel not in containers:
                for sig, kind in SIGS.items():
                    for m in re.finditer(re.escape(sig), data):
                        if m.start() != 0:
                            (nested_bin if is_bin else nested).append(dict(tree=tree, file=rel, kind=kind,
                                                                           offset=m.start()))
                            break
            if is_bin:
                rows.append(dict(tree=tree, file=rel, status='out_of_scope'))
                continue
            ents = listed.get((tree, rel), [])
            if not ents:
                problems.append(dict(tree=tree, file=rel, problem='no module report lists it'))
            elif len(ents) > 1:
                problems.append(dict(tree=tree, file=rel, problem='listed by several modules: ' +
                                     ', '.join(m for m, _ in ents)))
            else:
                mod, ent = ents[0]
                if not ent['ok']:
                    problems.append(dict(tree=tree, file=rel, problem=f'failed in {mod}'))
                elif ent['sha256'] != sha:
                    problems.append(dict(tree=tree, file=rel, problem=f'stale report {mod} (sha256 changed)'))
                else:
                    rows.append(dict(tree=tree, file=rel, status='ok', module=mod, opaque=ent['opaque'],
                                     bytes=ent['bytes']))
    for (t, rel), ents in sorted(listed.items()):
        if (t, rel) not in seen and t in trees:
            problems.append(dict(tree=t, file=rel, problem='in a report but no longer in the tree: ' +
                                 ', '.join(m for m, _ in ents)))
    ok = [r for r in rows if r['status'] == 'ok']
    per_module = {}
    for r in ok:
        m = per_module.setdefault(r['module'], dict(files=0, bytes=0, opaque=0))
        m['files'] += 1
        m['bytes'] += r['bytes']
        m['opaque'] += r['opaque']
    summary = dict(files_seen=len(rows) + len([p for p in problems if 'file' in p and 'no longer' not in p['problem']]),
                   ok=len(ok), out_of_scope=[r['file'] for r in rows if r['status'] == 'out_of_scope'],
                   problems=problems, unexpected_nested_signatures=nested, nested_signatures_in_binaries=nested_bin,
                   opaque_bytes=sum(r['opaque'] for r in ok), bytes_ok=sum(r['bytes'] for r in ok),
                   per_module=per_module)
    gate = not problems and not nested
    if write:
        os.makedirs(proj.p['reports'], exist_ok=True)
        json.dump(dict(summary, gate=gate), open(proj.report('completeness.json'), 'w'), indent=1)
    return gate, summary


def cmd_completeness(proj, a):
    ok, s = completeness(proj)
    return ok, dict(command='completeness', **s)


# ------------------------------------------------------------------------------------------- phases 4, 5
def orphan_line(log_path):
    last = None
    if os.path.exists(log_path):
        for line in open(log_path, errors='replace'):
            m = re.search(r'ORPHANS round \d+: orphan_instructions=(\d+)', line)
            if m:
                last = int(m.group(1))
    return last


def nfunctions(idx):
    """Function count of a run_recovery.sh index.json ({"functions": [...]} or a plain list)."""
    if idx is None:
        return None
    return len(idx['functions'] if isinstance(idx, dict) and 'functions' in idx else idx)


def name_failures(path):
    """(real failures, names already present at their address) of an apply_names.sh name_failures.txt."""
    if not os.path.exists(path):
        return None, 0
    lines = [l for l in open(path, errors='replace') if l.strip()]
    same = [l for l in lines if 'already exists at this address' in l]
    return len(lines) - len(same), len(same)


def cmd_recover(proj, a):
    rows, ok = [], True
    env = dict(os.environ, FORCE='1') if a.force else None
    for b in proj.binaries(a.binary):
        t0 = time.time()
        p = run(['sh', os.path.join(HERE, 'ghidra', 'run_recovery.sh'), b['binary'], b['decompiled'], b['project']],
                proj, env=env)
        row = dict(binary=b['file'], out=proj.rel(b['decompiled']), recovery_exit=p.returncode)
        if p.returncode == 0:
            row['orphan_instructions'] = orphan_line(os.path.join(b['decompiled'], 'recovery.log'))
            idx = os.path.join(b['decompiled'], 'index.json')
            row['functions'] = nfunctions(json.load(open(idx))) if os.path.exists(idx) else None
            c = run(PY + [os.path.join(HERE, 'code_coverage_check.py'), b['binary'], b['decompiled']], proj)
            row['coverage_check_exit'] = c.returncode
        row['seconds'] = round(time.time() - t0)
        row['ok'] = p.returncode == 0 and row.get('orphan_instructions') == 0 and row.get('coverage_check_exit') == 0
        ok &= row['ok']
        rows.append(row)
    return ok, dict(command='recover', binaries=rows)


def cmd_features(proj, a):
    rows = []
    for b in proj.binaries(a.binary):
        os.makedirs(b['analysis'], exist_ok=True)
        p = run(PY + [os.path.join(HERE, 'build_features.py'), b['decompiled'], b['binary'], b['analysis']] +
                (['--force'] if a.force else []), proj)
        meta = os.path.join(b['analysis'], 'features_meta.json')
        rows.append(dict(binary=b['file'], out=proj.rel(b['analysis']), ok=p.returncode == 0,
                         counts=json.load(open(meta)).get('counts') if p.returncode == 0 and os.path.exists(meta)
                         else None))
    return all(r['ok'] for r in rows), dict(command='features', binaries=rows)


def cmd_names(proj, a):
    rows = []
    for b in proj.binaries(a.binary):
        names = os.path.join(b['analysis'], 'names_apply.json')
        if not os.path.exists(names):
            rows.append(dict(binary=b['file'], ok=False, error=f'{proj.rel(names)} missing (phase 5 naming)'))
            continue
        p = run(['sh', os.path.join(HERE, 'ghidra', 'apply_names.sh'), b['binary'], b['project'], names, b['named']],
                proj)
        nf, same = name_failures(os.path.join(b['named'], 'name_failures.txt'))
        rows.append(dict(binary=b['file'], out=proj.rel(b['named']), exit=p.returncode, name_failures=nf,
                         already_present=same, ok=p.returncode in (0, 3) and nf == 0))
    return all(r['ok'] for r in rows), dict(command='names', binaries=rows)


# ------------------------------------------------------------------------------------------- phase 5b
def cmd_reassemble(proj, a):
    rows = []
    work = os.path.join(proj.p['build'], 'work', 'reassemble')
    os.makedirs(work, exist_ok=True)
    for b in proj.binaries(a.binary):
        t0 = time.time()
        row = dict(binary=b['file'], text=proj.rel(b['reassembled']))
        have = os.path.exists(os.path.join(b['reassembled'], 'layout.json'))
        if have and a.split and not a.force:
            raise ConfigError(f'{proj.rel(b["reassembled"])} exists: --split would overwrite it (add --force)')
        if not have or a.split:
            names = os.path.join(b['analysis'], 'names_apply.json')
            p = run(PY + [os.path.join(HERE, 'reassemble.py'), 'split', b['binary'], b['decompiled'],
                          b['reassembled']] + (['--names', names] if os.path.exists(names) else []), proj)
            row['split'] = p.returncode == 0
            if p.returncode:
                rows.append(dict(row, ok=False))
                continue
        out = os.path.join(work, b['file'])
        os.makedirs(os.path.dirname(out), exist_ok=True)          # binaries can live in subfolders
        cache = (['--cache', os.path.join(work, f'asm_cache_{b["name"]}.json')] if a.cache else [])
        p = run(PY + [os.path.join(HERE, 'reassemble.py'), 'build', b['reassembled'], out] + cache, proj)
        built = sha256_file(out) if p.returncode == 0 and os.path.exists(out) else None
        orig = sha256_file(b['binary']) if os.path.exists(b['binary']) else None
        lay = json.load(open(os.path.join(b['reassembled'], 'layout.json')))
        row.update(built_sha256=built, original_sha256=orig, identical=bool(built) and built == orig,
                   cached=bool(a.cache), stats=lay.get('stats'), seconds=round(time.time() - t0))
        row['ok'] = row['identical']
        os.makedirs(proj.report('reassemble'), exist_ok=True)
        json.dump(row, open(proj.report('reassemble', f'{b["name"]}.json'), 'w'), indent=1)
        rows.append(row)
    return all(r['ok'] for r in rows), dict(command='reassemble', binaries=rows)


# -------------------------------------------------------------------------------------------- phase 6
def cmd_skeleton(proj, a):
    rows = []
    bl = proj.binaries(a.binary) if a.binary else proj.binaries(matching_only=True)
    for b in bl:
        if glob.glob(os.path.join(b['src'], '*.cpp')) and not a.force:
            raise ConfigError(f'{proj.rel(b["src"])} already holds units (use --force to overwrite them)')
        nf = os.path.join(b['analysis'], 'names_final.json')
        p = run(PY + [os.path.join(HERE, 'phase6_skeleton.py'), nf, b['src'], '--module', b['name'],
                      '--decompiled', b['named']], proj)
        rows.append(dict(binary=b['file'], out=proj.rel(b['src']), ok=p.returncode == 0,
                         units=len(glob.glob(os.path.join(b['src'], '*.cpp')))))
    return all(r['ok'] for r in rows), dict(command='skeleton', binaries=rows)


def match_unit(proj, b, unit_path, obj_dir, pe, env, default_flags, show_stubs):
    """Compile one unit with the original compiler and compare its annotated functions (tools' match.sh)."""
    name = os.path.basename(unit_path)[:-4]
    srcdir = os.path.dirname(unit_path)
    obj = os.path.join(obj_dir, name + '.obj')
    if os.path.exists(obj):
        os.remove(obj)
    text = open(unit_path, errors='replace').read()
    m = re.search(r'^// CLFLAGS: *(.*)$', text, re.M)
    flags = (m.group(1) if m else None) or env.get('CLFLAGS') or default_flags
    rel = os.path.relpath(obj_dir, srcdir).replace('/', '\\')
    cmd = ['sh', os.path.join(HERE, 'msvc.sh'), 'cl', '/nologo', '/c'] + flags.split() + \
        [f'/Fo{rel}\\{name}.obj', os.path.basename(unit_path)]
    c = subprocess.run(cmd, cwd=srcdir, env=env, capture_output=True, text=True, errors='replace')
    out = c.stdout + c.stderr
    if c.returncode or not os.path.exists(obj):
        return dict(unit=name, compiled=False, error=(out + f'COMPILE FAILED: {name}\n')[-600:])
    repsrc = unit_path
    if show_stubs:
        repsrc = os.path.join(obj_dir, name + '.withstubs.cpp')
        open(repsrc, 'w').write(text.replace('// STUB: ', '// FUNCTION: '))
    r = subprocess.run(PY + [os.path.join(HERE, 'objcmp.py'), 'report', '--pe', pe, '--src', repsrc, '--obj', obj,
                             '--module', b['name'], '--functions', os.path.join(b['named'], 'index.json'), '-v'],
                       cwd=proj.root, env=env, capture_output=True, text=True, errors='replace')
    out += r.stdout + r.stderr
    tagged = {int(x, 16) for x in NONMATCH.findall(text)}
    rows = [dict(status=m.group(1), addr='0x' + m.group(2).lstrip('0'), ratio=m.group(3), size=m.group(4))
            for m in LINE.finditer(out)]
    for x in rows:          # FUNCTIONs tagged // NONMATCHING: in the source build, not expected to match
        if x['status'] == 'DIFF' and int(x['addr'], 16) in tagged:
            x['status'] = 'NONMATCHING'
    s = SUM.search(out)
    ident, annotated, stubs, bok, btot = (int(x) for x in s.groups()) if s else (0, 0, 0, 0, 0)
    return dict(unit=name, compiled=True, identical=ident, annotated=annotated, stubs=stubs,
                bytes_identical=bok, bytes_total=btot, functions=rows)


def match_binary(proj, b, units=None, jobs=4, pe=None):
    env = proj.toolchain_env()
    pe = pe or env.get('MATCH_PE') or b['binary']
    files = sorted(glob.glob(os.path.join(b['src'], '*.cpp')))
    if units:
        files = [f for f in files if os.path.basename(f)[:-4] in units]
    obj_dir = os.path.join(proj.p['build'], 'obj', b['name'])
    os.makedirs(obj_dir, exist_ok=True)
    flags = proj.cfg.get('toolchain', {}).get('flags', '/O2')
    show = env.get('SHOW_STUBS', '0') == '1'
    log(f'match {b["name"]}: {len(files)} units, compared with {proj.rel(pe)}')
    with cf.ThreadPoolExecutor(max(1, jobs)) as ex:
        res = list(ex.map(lambda f: match_unit(proj, b, f, obj_dir, pe, env, flags, show), files))
    tot = dict(units=len(res), compile_failed=sum(1 for r in res if not r['compiled']),
               functions_identical=sum(r.get('identical', 0) for r in res),
               functions_stub=sum(r.get('stubs', 0) for r in res),
               functions_diff=sum(1 for r in res for f in r.get('functions', []) if f['status'] == 'DIFF'),
               functions_nonmatching=sum(1 for r in res for f in r.get('functions', []) if f['status'] == 'NONMATCHING'),
               bytes_identical=sum(r.get('bytes_identical', 0) for r in res))
    os.makedirs(proj.report('match'), exist_ok=True)
    status = dict(totals=tot, units=res)
    if not units:                # a partial run does not replace the whole binary's status
        json.dump(status, open(proj.report('match', f'{b["name"]}.json'), 'w'), indent=1)
    for r in res:
        if not r['compiled']:
            log('COMPILE FAILED', r['unit'])
    return status, obj_dir


def cmd_match(proj, a):
    bl = proj.binaries(a.binary) if a.binary else proj.binaries(matching_only=True)
    units = set(a.units.split(',')) if a.units else None
    out, ok = {}, True
    t0 = time.time()
    for b in bl:
        st, _ = match_binary(proj, b, units, a.jobs)
        out[b['name']] = st['totals']
        ok &= st['totals']['functions_diff'] == 0 and st['totals']['compile_failed'] == 0
    return ok, dict(command='match', binaries=out, seconds=round(time.time() - t0),
                    status_files=[proj.rel(proj.report('match', f'{b["name"]}.json')) for b in bl] if not units else [])


# -------------------------------------------------------------------------------------------------- build
def entries(decoded, module, exts):
    """Decoded entries of a module: directories decoded/<module>/<path of the file> (path relative to its tree;
    archive members as <archive>/<member>). A decoded file is a directory named like the file that holds
    files itself (an archive's directory only holds its members' directories)."""
    top = os.path.join(decoded, module)
    out = []
    for r, ds, fs in os.walk(top):
        keep = []
        for d in ds:
            full = os.path.join(r, d)
            if os.path.splitext(d)[1].lower() in exts and any(os.path.isfile(os.path.join(full, x))
                                                              for x in os.listdir(full)):
                out.append(os.path.relpath(full, top).replace(os.sep, '/'))
            else:
                keep.append(d)
        ds[:] = keep
    return sorted(out)


def encode_one(job):
    formats_dir, module, src, dst = job
    data = load_format(formats_dir, module).encode_from_dir(src)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, 'wb') as f:
        f.write(data)
    return len(data)


def build_data(proj, out, jobs):
    """Every data file from decoded/<module>/ with the project's encoders, in config order; archive members are
    rebuilt into a copy of their archive's decoded folder (members/<path>) and the archive is packed last."""
    fdir, dec = proj.p['formats'], proj.p['decoded']
    cfg_archives = set(proj.cfg.get('archives', []))
    plan, archives = [], []                      # archives: (module, rel) in config order of their modules
    for f in proj.formats():
        exts = {e.lower() for e in load_format(fdir, f['module']).EXTS}
        for rel in entries(dec, f['module'], exts):
            (archives if rel in cfg_archives else plan).append((f['module'], rel))
    members_dir = {f['module']: f.get('members', 'members') for f in proj.formats()}
    stage = tempfile.mkdtemp(prefix='archives_', dir=os.path.join(proj.p['build'], 'work'))
    for m, arc in archives:
        shutil.copytree(os.path.join(dec, m, arc), os.path.join(stage, arc))
    work = []
    for m, rel in plan:
        am = next(((am, a_) for am, a_ in archives if rel.startswith(a_ + '/')), None)
        dst = (os.path.join(stage, am[1], members_dir[am[0]], rel[len(am[1]) + 1:]) if am else os.path.join(out, rel))
        work.append((fdir, m, os.path.join(dec, m, rel), dst))
    t = time.time()
    with cf.ProcessPoolExecutor(max(1, jobs)) as ex:
        done = list(ex.map(encode_one, work))
    log(f'data: {len(done)} files from {proj.rel(dec)}/ ({time.time() - t:.0f} s)')
    t = time.time()
    for m, arc in archives:
        data = load_format(fdir, m).encode_from_dir(os.path.join(stage, arc))
        os.makedirs(os.path.dirname(os.path.join(out, arc)) or out, exist_ok=True)
        with open(os.path.join(out, arc), 'wb') as f:
            f.write(data)
    log(f'data: {len(archives)} archives packed ({time.time() - t:.0f} s)')
    shutil.rmtree(stage)
    return len(done) + len(archives)


def reassemble_to(proj, src_dir, dst, cache=None):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    p = run(PY + [os.path.join(HERE, 'reassemble.py'), 'build', src_dir, dst] + (['--cache', cache] if cache else []),
            proj)
    return p.returncode == 0 and os.path.exists(dst)


def build_exe(proj, b, out, mode, work, jobs, ref=None, cache=None):
    """A matching binary: every unit compiled, link.exe through relink.py; source = all // FUNCTIONs, code may
    move (--free, then every original branch/pointer checked); identical = only matching functions + the
    post-link facts of the reference."""
    ref = ref or b['binary']
    st, obj_dir = match_binary(proj, b, None, jobs, pe=ref)
    if st['totals']['compile_failed']:
        log(f'compile: {st["totals"]["compile_failed"]} units failed')
        return None
    log(f'compile: every unit compiled ({st["totals"]["functions_identical"]} functions identical)')
    env = proj.toolchain_env()
    R = lambda p: os.path.relpath(p, proj.root)
    symbols = os.path.join(work, f'symbols_{b["name"]}.json')
    cmd = PY + [os.path.join(HERE, 'hybrid_link.py'), 'map', '--pe', R(ref), '--src', R(b['src']), '--obj', R(obj_dir),
                '--module', b['name'], '--functions', R(os.path.join(b['named'], 'index.json')),
                '--instructions', R(os.path.join(b['decompiled'], 'instructions.tsv')), '--out', R(symbols)] + \
        (['--all'] if mode == 'source' else [])
    if run(cmd, proj, env=env).returncode:
        log('map: FAILED (unresolved symbols or layout conflicts; see above)')
        return None
    ld = os.path.join(work, f'relink_{b["name"]}')
    cmd = PY + [os.path.join(HERE, 'relink.py'), 'prepare', R(b['reassembled']), R(symbols), R(b['decompiled']), R(ld)]
    for l in proj.libdirs():
        cmd += ['--libdir', l]
    cmd += (['--free'] if mode == 'source' else []) + (['--cache', R(cache)] if cache else [])
    if subprocess.run(cmd, cwd=proj.root, env=env, stdout=subprocess.DEVNULL).returncode:
        log('prepare: FAILED')
        return None
    subprocess.run(PY + [os.path.join(HERE, 'relink.py'), 'link', R(ld), R(ref)], cwd=proj.root, env=env,
                   stdout=subprocess.DEVNULL)
    exe = os.path.join(ld, 'relinked.exe')
    if not os.path.exists(exe):
        log('link: FAILED; see', os.path.join(ld, 'link.rsp'))
        return None
    if mode == 'source':
        c = run(PY + [os.path.join(HERE, 'relink.py'), 'check', R(ld), R(ref), R(symbols),
                      R(os.path.join(b['decompiled'], 'instructions.tsv')),
                      R(os.path.join(b['decompiled'], 'index.json'))], proj, env=env)
        if c.returncode:
            log('check: FAILED')
            return None
    else:
        run(PY + [os.path.join(HERE, 'relink.py'), 'finish', R(ld), R(ref)], proj, env=env)
        exe = os.path.join(ld, 'final.exe')
    dst = os.path.join(out, b['file'])
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy(exe, dst)
    return dict(binary=b['file'], functions_identical=st['totals']['functions_identical'],
                functions_nonmatching=st['totals']['functions_nonmatching'])


def compare_trees(game, out):
    """Every file of the game folder against the build: identical / different / missing; plus extra files."""
    rows = []
    for rel in walk_files(game):
        p = os.path.join(out, rel)
        if not os.path.exists(p):
            rows.append((rel, 'missing'))
        else:
            rows.append((rel, 'identical' if sha256_file(os.path.join(game, rel)) == sha256_file(p) else 'different'))
    have = set(walk_files(game))
    extra = [r for r in walk_files(out) if r not in have]
    return rows, extra


def window_titles(owner_prefix='wine'):
    """Titles of on-screen windows whose owner starts with owner_prefix (macOS CoreGraphics window list; needs no
    screen-recording access). None when not on macOS."""
    if sys.platform != 'darwin':
        return None
    import ctypes, ctypes.util
    cf_ = ctypes.cdll.LoadLibrary(ctypes.util.find_library('CoreFoundation'))
    cg = ctypes.cdll.LoadLibrary(ctypes.util.find_library('CoreGraphics'))
    V = ctypes.c_void_p
    cg.CGWindowListCopyWindowInfo.restype = V
    cg.CGWindowListCopyWindowInfo.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    cf_.CFArrayGetCount.restype = ctypes.c_long
    cf_.CFArrayGetCount.argtypes = [V]
    cf_.CFArrayGetValueAtIndex.restype = V
    cf_.CFArrayGetValueAtIndex.argtypes = [V, ctypes.c_long]
    cf_.CFDictionaryGetValue.restype = V
    cf_.CFDictionaryGetValue.argtypes = [V, V]
    cf_.CFStringCreateWithCString.restype = V
    cf_.CFStringCreateWithCString.argtypes = [V, ctypes.c_char_p, ctypes.c_uint32]
    cf_.CFStringGetCString.argtypes = [V, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
    cf_.CFRelease.argtypes = [V]

    def s(x):
        return cf_.CFStringCreateWithCString(None, x.encode(), 0x08000100)

    def text(v):
        buf = ctypes.create_string_buffer(1024)
        if v:
            cf_.CFStringGetCString(v, buf, 1024, 0x08000100)
        return buf.value.decode('utf-8', 'replace')
    k_owner, k_name = s('kCGWindowOwnerName'), s('kCGWindowName')
    arr = cg.CGWindowListCopyWindowInfo(1 | 16, 0)       # on-screen only, excluding desktop elements
    out = []
    for i in range(cf_.CFArrayGetCount(arr)):
        d = cf_.CFArrayGetValueAtIndex(arr, i)
        if text(cf_.CFDictionaryGetValue(d, k_owner)).lower().startswith(owner_prefix):
            out.append(text(cf_.CFDictionaryGetValue(d, k_name)))
    cf_.CFRelease(arr)
    cf_.CFRelease(k_owner)
    cf_.CFRelease(k_name)
    return out


def run_game(proj, out, tries=3, wait=30):
    """Start the build under Wine and wait for its window (macOS window list; elsewhere: the process is still
    alive after the wait). Several tries: Wine on macOS sometimes ends a starting game silently."""
    rc = proj.cfg.get('run', {})
    exe = rc.get('exe') or next((b['file'] for b in proj.binaries() if b['file'].lower().endswith('.exe')), None)
    if not exe:
        raise ConfigError('run.exe not set in decomp.json')
    want = rc.get('window', os.path.splitext(os.path.basename(exe))[0])
    prefix = os.environ.get('WINEPREFIX') or os.path.expanduser(rc.get('wineprefix', '~/.wine'))
    env = dict(os.environ, WINEPREFIX=prefix, WINEDEBUG='-all')
    cwd = os.path.join(out, os.path.dirname(exe))
    for t in range(1, tries + 1):
        subprocess.run(['wineserver', '-k'], env=env, capture_output=True)
        time.sleep(2)
        p = subprocess.Popen(['wine', os.path.basename(exe)], cwd=cwd, env=env, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        title, alive = None, False
        if window_titles() is None:              # no window list on this host: liveness only
            time.sleep(wait)
            alive = p.poll() is None
            title = '(window not checked: no window list on this host)' if alive else None
        else:
            for _ in range(wait):
                time.sleep(1)
                ts = window_titles()
                hit = [x for x in ts if x.startswith(want)]
                if hit:
                    title = hit[0]
                    break
                if any(x in ('Program Error', 'Wine Debugger') for x in ts):
                    break
            if title:
                time.sleep(5)
                alive = any(x.startswith(want) for x in window_titles())
        subprocess.run(['wineserver', '-k'], env=env, capture_output=True)
        p.wait()
        log(f'run {t}: window {title!r}, still running 5 s later: {alive}')
        if title and alive:
            return title, t
    return None, tries


def cmd_build(proj, a):
    out = proj.abs(a.out) if a.out else os.path.join(proj.p['build'], 'game')
    work = os.path.join(proj.p['build'], 'work')
    os.makedirs(out, exist_ok=True)
    os.makedirs(work, exist_ok=True)
    t0 = time.time()
    res = dict(command='build', mode=a.mode, out=proj.rel(out), no_original=a.no_original)
    if not a.skip_data:
        res['data_files'] = build_data(proj, out, a.jobs)
    res['binaries'] = []
    for b in proj.binaries():
        if b['matching']:
            continue
        if not reassemble_to(proj, b['reassembled'], os.path.join(out, b['file'])):
            return False, dict(res, error=f'{b["file"]}: reassembly failed')
        log(f'{b["file"]}: rebuilt from {proj.rel(b["reassembled"])}')
        res['binaries'].append(dict(binary=b['file'], source=proj.rel(b['reassembled'])))
    for b in proj.binaries(matching_only=True):
        ref = cache = None
        if a.no_original:      # the reference (symbol addresses, .reloc reserve, post-link facts) from the text
            ref = os.path.join(work, 'reference', b['file'])
            cache = os.path.join(work, f'asm_cache_{b["name"]}.json')
            if not reassemble_to(proj, b['reassembled'], ref, cache):
                return False, dict(res, error=f'{b["file"]}: reference reassembly failed')
            log(f'reference: {b["file"]} assembled from {proj.rel(b["reassembled"])} (the game folder is not read)')
        r = build_exe(proj, b, out, a.mode, work, a.jobs, ref, cache)
        if not r:
            return False, dict(res, error=f'{b["file"]}: build failed (see the log)')
        res['binaries'].append(r)
    if a.no_original:
        res['files'] = dict(built=len(walk_files(out)), compared='no (--no-original)')
        rows = []
    else:
        rows, extra = compare_trees(proj.p['game'], out)
        summary = {}
        for _, st in rows:
            summary[st] = summary.get(st, 0) + 1
        res['files'] = summary
        res['different'] = [r for r, st in rows if st != 'identical']
        res['extra'] = extra
    res['seconds'] = round(time.time() - t0)
    ok = a.mode == 'source' or a.no_original or (rows and res['files'].get('identical', 0) == len(rows))
    if a.run:
        title, tries = run_game(proj, out)
        res['game_window'] = title or 'NOT SHOWN'
        res['run_tries'] = tries
        ok = ok and bool(title)
    res['ok'] = bool(ok)
    os.makedirs(proj.p['reports'], exist_ok=True)
    json.dump(dict(res, finished=time.strftime('%Y-%m-%dT%H:%M:%S')), open(proj.report('build.json'), 'w'), indent=1)
    return bool(ok), res


def cmd_verify(proj, a):
    out = proj.abs(a.out) if a.out else os.path.join(proj.p['build'], 'game')
    if not os.path.isdir(out):
        raise ConfigError(f'no build folder {proj.rel(out)}')
    if not os.path.isdir(proj.p['game']):
        raise ConfigError(f'no game folder {proj.rel(proj.p["game"])}')
    rows, extra = compare_trees(proj.p['game'], out)
    summary = {}
    for _, st in rows:
        summary[st] = summary.get(st, 0) + 1
    res = dict(command='verify', out=proj.rel(out), game=proj.rel(proj.p['game']), files=summary,
               different=[r for r, st in rows if st == 'different'], missing=[r for r, st in rows if st == 'missing'],
               extra=extra)
    ok = bool(rows) and summary.get('identical', 0) == len(rows) and not extra
    json.dump(dict(res, ok=ok), open(proj.report('verify.json'), 'w'), indent=1)
    return ok, res


# ------------------------------------------------------------------------------------------------- status
def cmd_status(proj, a):
    rows = []

    def row(phase, gate, detail):
        rows.append(dict(phase=phase, gate=gate, detail=detail))

    def jload(p):
        try:
            return json.load(open(p))
        except (OSError, ValueError):
            return None
    game = proj.p['game']
    # 1 intake
    if not os.path.isdir(game):
        row('1 intake', 'not run', f'no game folder {proj.rel(game)}')
    else:
        n = len(walk_files(game))
        man = jload(proj.p['manifest'])
        if man:
            sys.path.insert(0, HERE)
            import intake
            cur = intake.manifest(game)['files']
            same = cur.keys() == man['files'].keys() and all(cur[k]['sha256'] == man['files'][k]['sha256'] for k in cur)
            row('1 intake', 'ok' if same else 'FAIL',
                f'{n} files; {"identical to" if same else "DIFFERENT from"} {proj.rel(proj.p["manifest"])}')
        else:
            it = jload(proj.report('intake.json'))
            row('1 intake', ('ok' if it['ok'] else 'FAIL') if it else 'open', f'{n} files; no manifest yet')
    # 2 inventory, archives
    inv = jload(proj.report('inventory.json'))
    if inv:
        un = inventory_gate(proj, inv)
        row('2 inventory', 'ok' if not un else 'FAIL', f'{len(inv["files"])} files, {len(inv.get("unclassified", []))} '
            f'without magic, {len(un)} not handled by a configured module')
    else:
        row('2 inventory', 'not run', '')
    mem = jload(os.path.join(proj.p['extracted'], MEMBERS_JSON))
    arcs = proj.cfg.get('archives', [])
    if mem is not None:
        miss = [x for x in arcs if x not in mem]
        row('2 archives', 'ok' if not miss else 'FAIL', ', '.join(f'{k}: {len(v)} members' for k, v in mem.items()) +
            (f'; not extracted: {miss}' if miss else ''))
    else:
        row('2 archives', 'not run' if arcs else 'ok', '' if arcs else 'no archives configured')
    # 3 decode
    mods = []
    for f in proj.formats():
        for t in f['trees']:
            r = jload(proj.report(t, f'{f["module"]}.json'))
            mods.append((f'{t}/{f["module"]}', r))
    if mods:
        done = [(m, r) for m, r in mods if r]
        files = sum(r['files'] for _, r in done)
        passed = sum(r['passed'] for _, r in done)
        gate, comp = completeness(proj, write=False)
        row('3 decode', 'ok' if gate and len(done) == len(mods) and passed == files else
            ('FAIL' if done else 'not run'),
            f'{len(done)}/{len(mods)} module reports, {passed}/{files} files identical, '
            f'opaque {sum(r["opaque_bytes"] for _, r in done)} bytes; completeness: {comp["ok"]} ok, '
            f'{len(comp["problems"])} problems, {len(comp["unexpected_nested_signatures"])} nested signatures')
    else:
        row('3 decode', 'not run', 'no formats configured')
    for b in proj.binaries():
        nm = b['name']
        idx = jload(os.path.join(b['decompiled'], 'index.json'))
        orph = orphan_line(os.path.join(b['decompiled'], 'recovery.log'))
        cc = jload(os.path.join(b['decompiled'], 'coverage_check.json'))
        mbz = (cc or {}).get('summary', {}).get('must_be_zero')
        if idx is None:
            row(f'4 recover {nm}', 'not run', '')
        else:
            good = orph == 0 and mbz is not None and not any(mbz.values())
            row(f'4 recover {nm}', 'ok' if good else 'FAIL',
                f'{nfunctions(idx)} functions, orphan instructions {orph}, coverage check '
                f'{"clean" if mbz is not None and not any(mbz.values()) else ("not run" if mbz is None else mbz)}')
        fm = jload(os.path.join(b['analysis'], 'features_meta.json'))
        row(f'5 features {nm}', 'ok' if fm else 'not run',
            f'{fm["counts"]["functions"]} functions, {fm["counts"].get("chunks")} chunks' if fm else '')
        nidx = jload(os.path.join(b['named'], 'index.json'))
        apply_ = os.path.join(b['analysis'], 'names_apply.json')
        nf, same = name_failures(os.path.join(b['named'], 'name_failures.txt'))
        if nidx is None:
            row(f'5 names {nm}', 'not run', 'names_apply.json present' if os.path.exists(apply_) else '')
        else:
            napplied = len(jload(apply_) or {}) if os.path.exists(apply_) else 0
            row(f'5 names {nm}', 'ok' if not nf else 'FAIL', f'{napplied} names in names_apply.json, {nf or 0} '
                f'failures' + (f' ({same} already present at their address)' if same else ''))
        ra = jload(proj.report('reassemble', f'{nm}.json'))
        if ra:
            row(f'5b reassemble {nm}', 'ok' if ra['identical'] else 'FAIL',
                f'{"identical" if ra["identical"] else "DIFFERENT"} {(ra["built_sha256"] or "")[:16]}'
                f'{" (cached)" if ra.get("cached") else ""}')
        else:
            have = os.path.exists(os.path.join(b['reassembled'], 'layout.json'))
            row(f'5b reassemble {nm}', 'open' if have else 'not run',
                'text present, not verified by the runner' if have else '')
        if b['matching']:
            units = len(glob.glob(os.path.join(b['src'], '*.cpp')))
            st = jload(proj.report('match', f'{nm}.json'))
            if st:
                t = st['totals']
                row(f'6 match {nm}', 'ok' if t['functions_diff'] == 0 and t['compile_failed'] == 0 else 'FAIL',
                    f'{t["units"]} units, {t["functions_identical"]} identical, {t["functions_nonmatching"]} '
                    f'nonmatching, {t["functions_diff"]} diff, {t["functions_stub"]} stubs, '
                    f'{t["compile_failed"]} compile failures')
            else:
                row(f'6 match {nm}', 'not run', f'{units} units' if units else 'no units (skeleton)')
    bj = jload(proj.report('build.json'))
    if bj:
        row('build', 'ok' if bj.get('ok') else 'FAIL', f'{bj["mode"]}{" --no-original" if bj.get("no_original") else ""} '
            f'-> {bj["out"]}: {bj.get("files")}{"; window " + bj["game_window"] if "game_window" in bj else ""} '
            f'({bj.get("finished", "")})')
    else:
        row('build', 'not run', '')
    vj = jload(proj.report('verify.json'))
    row('verify', ('ok' if vj['ok'] else 'FAIL') if vj else 'not run',
        f'{vj["out"]}: {vj["files"]}, extra {len(vj["extra"])}' if vj else '')
    order = ['1', '2', '3', '4', '5', '5b', '6', 'build', 'verify']
    rows.sort(key=lambda r: order.index(r['phase'].split()[0]))          # stable: binaries keep config order
    w = max(len(r['phase']) for r in rows)
    log(f'{proj.cfg.get("game", "")}\n{"phase":{w}}  {"gate":8} detail')
    for r in rows:
        log(f'{r["phase"]:{w}}  {r["gate"]:8} {r["detail"]}')
    return all(r['gate'] == 'ok' for r in rows), dict(command='status', game=proj.cfg.get('game'), phases=rows)


# --------------------------------------------------------------------------------------------------- main
def main(argv):
    ap = argparse.ArgumentParser(prog='pipeline.py', description=__doc__.split('\n')[0])
    ap.add_argument('--project', default='.')
    sp = ap.add_subparsers(dest='cmd')
    s = sp.add_parser('init'); s.add_argument('--game', required=True); s.add_argument('--force', action='store_true')
    s = sp.add_parser('intake'); s.add_argument('installer'); s.add_argument('--language')
    s.add_argument('--force', action='store_true')
    sp.add_parser('inventory')
    s = sp.add_parser('archives'); s.add_argument('--force', action='store_true')
    s = sp.add_parser('decode'); s.add_argument('--module'); s.add_argument('--jobs', type=int, default=4)
    sp.add_parser('completeness')
    for c in ('recover', 'features', 'names', 'reassemble', 'skeleton'):
        s = sp.add_parser(c); s.add_argument('--binary')
        if c != 'names':
            s.add_argument('--force', action='store_true')
        if c == 'reassemble':
            s.add_argument('--split', action='store_true'); s.add_argument('--cache', action='store_true')
    s = sp.add_parser('match'); s.add_argument('--binary'); s.add_argument('--units')
    s.add_argument('--jobs', type=int, default=4)
    s = sp.add_parser('build'); s.add_argument('--mode', choices=['source', 'identical'], default='source')
    s.add_argument('--out'); s.add_argument('--no-original', action='store_true')
    s.add_argument('--skip-data', action='store_true'); s.add_argument('--jobs', type=int, default=6)
    s.add_argument('--run', action='store_true')
    s = sp.add_parser('verify'); s.add_argument('--out')
    sp.add_parser('status')
    argv = list(argv)                      # --project may come after the command too
    for i, x in enumerate(argv):
        if x == '--project' and i + 1 < len(argv):
            argv = argv[i:i + 2] + argv[:i] + argv[i + 2:]
            break
        if x.startswith('--project='):
            argv = [x] + argv[:i] + argv[i + 1:]
            break
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help(sys.stderr)
        return 2
    try:
        proj = Project(a.project, need_config=a.cmd != 'init')
        ok, res = globals()['cmd_' + a.cmd](proj, a)
    except ConfigError as e:
        print(json.dumps(dict(command=a.cmd, error=str(e)), indent=1))
        return 2
    print(json.dumps(res, indent=1))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
