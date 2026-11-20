#!/usr/bin/env python3
"""Run the skill's phases on a project folder from one config file, decomp.json (references/pipeline.md).

  pipeline.py [--project DIR] <command> [options]

  init --game NAME [--force]          decomp.json skeleton (PE binaries found in the game folder listed),
                                      .gitignore lines for game-derived folders, the project folders
  intake <setup.exe | installed dir> [--language L] [--force]
                                      step 1: extract (scripts/intake.py) into <work>/installer, copy the game
                                      folder to paths.game, GOG hashdb gate, SHA-256 manifest: written to
                                      paths.manifest, or compared with it when it already exists
  inventory                           step 2: scripts/inventory.py census -> <reports>/inventory.json; files no
                                      magic matched must be handled by a configured module or be a binary
  archives [--force]                  extract the configured archives -> <extracted>/<archive>/ + _members.json
  decode [--module M] [--jobs N]      step 3d: scripts/verify.py for every (module, tree) ->
                                      <reports>/<tree>/<module>.json, decoded/<module>/; then the completeness gate
  completeness                        the step-3d gate alone (also run by decode) -> <reports>/completeness.json
  recover [--binary B] [--force]      step 3a: ghidra/run_recovery.sh + code_coverage_check.py per binary
  features [--binary B] [--force]     step 3b input: build_features.py -> <analysis>/<B>/
  names [--binary B]                  step 3b: ghidra/apply_names.sh with <analysis>/<B>/names_apply.json -> named
  status                              one table: every step, its gate, read from the files on disk

Each command prints progress to stderr and a JSON summary to stdout, and exits 0 only when its gate holds
(1 gate failed, 2 bad arguments or config). Nothing here is game-specific: names, paths, archives, format
modules and binaries all come from decomp.json; paths may be absolute.
Python stdlib + Ghidra only. Run with python3 -I.
"""
import argparse, concurrent.futures as cf, hashlib, importlib.util, json, os, re, shutil, subprocess, sys
import time, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PY = [sys.executable, '-I']
DEFAULT_PATHS = {'game': 'work/game', 'extracted': 'extracted', 'decoded': 'decoded', 'reports': 'reports',
                 'formats': 'tools/formats', 'analysis': 'analysis', 'build': 'build',
                 'work': 'work', 'manifest': 'manifests/game.json'}
GITIGNORE = ['# Game-derived content (copyrighted; regenerate locally from your own installer)', '/extracted/',
             '/decoded/', '/previews/', '/decompiled*/', '/analysis/', '/work/', '/build/',
             '# clean room: implementer workspaces (copies), the oracle\'s traces', '/cleanroom/workspaces/',
             '/rewrite/harness/oracle/', '__pycache__/', '*.pyc', '.DS_Store']
SIGS = {b'PK\x03\x04': 'zip', b'OggS': 'ogg', b'RIFF': 'riff', b'\x89PNG\r\n\x1a\n': 'png'}
MEMBERS_JSON = '_members.json'                 # written by `archives` into the extracted tree


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

    def binaries(self, name=None):
        out = []
        for b in self.cfg.get('binaries', []):
            if 'file' not in b:
                raise ConfigError(f'binaries entry without "file": {b}')
            stem = os.path.splitext(os.path.basename(b['file']))[0]
            nm = b.get('name', stem)
            low = stem.lower()
            r = dict(name=nm, file=b['file'], stem=stem,
                     binary=os.path.join(self.p['game'], b['file']),
                     decompiled=self.abs(b.get('decompiled', f'decompiled_{low}')),
                     named=self.abs(b.get('named', f'decompiled_named_{low}')),
                     analysis=self.abs(b['analysis']) if 'analysis' in b else os.path.join(self.p['analysis'], nm),
                     project=self.abs(b['ghidra_project']) if 'ghidra_project' in b
                     else os.path.join(self.p['work'], f'ghidra_{stem}'))
            out.append(r)
        if name:
            out = [b for b in out if name in (b['name'], b['file'], b['stem'])]
            if not out:
                raise ConfigError(f'no binary {name!r} in decomp.json')
        return out

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
                                 'named': f'decompiled_named_{stem.lower()}'})
    cfg = {'game': a.game, 'paths': {k: v for k, v in DEFAULT_PATHS.items()}, 'archives': [], 'formats': [],
           'containers': [], 'binaries': binaries}
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
                      gitignore_added=add, next='fill in archives/formats/containers, then intake')


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
    os.makedirs(proj.p['reports'], exist_ok=True)
    pc = run(PY + [os.path.join(HERE, 'protection_check.py'), game, '--json', proj.report('protection.json')], proj,
             capture=True)
    if pc.stderr:
        log(pc.stderr.rstrip('\n'))
    res['protection'] = {0: 'clean', 1: 'FOUND: copy protection or packer (reports/protection.json); stop'}.get(
        pc.returncode, 'error')
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
    ok = man_ok and (hp.returncode == 0 or (hp.returncode == 2 and 'compared' in res['manifest'])) and \
        pc.returncode == 0
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
    """Step-3d gate without a routing table: a file is covered when exactly one module's report
    (<reports>/<tree>/<module>.json) lists it, ok, with the SHA-256 it has now, or when it is a configured
    archive that `archives` extracted (in _members.json) and no reader lists; binaries are out of scope;
    no embedded container signature away from offset 0 except in configured containers (and binaries,
    whose hits are code constants and strings: listed, step 3a covers them)."""
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
    archives = set(proj.cfg.get('archives', []))
    try:                             # archives extracted by `archives` (members CRC-checked) need no reader
        members = json.load(open(os.path.join(proj.p['extracted'], MEMBERS_JSON)))
    except (OSError, ValueError):
        members = {}
    members = members if isinstance(members, dict) else {}
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
            if not ents and tree == 'game' and rel in archives and rel in members:
                rows.append(dict(tree=tree, file=rel, status='extracted'))
                continue
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
                   archives_extracted=[r['file'] for r in rows if r['status'] == 'extracted'],
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


# ------------------------------------------------------------------------------------------- steps 3a, 3b
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
            rows.append(dict(binary=b['file'], ok=False, error=f'{proj.rel(names)} missing (step 3b naming)'))
            continue
        p = run(['sh', os.path.join(HERE, 'ghidra', 'apply_names.sh'), b['binary'], b['project'], names, b['named']],
                proj)
        nf, same = name_failures(os.path.join(b['named'], 'name_failures.txt'))
        rows.append(dict(binary=b['file'], out=proj.rel(b['named']), exit=p.returncode, name_failures=nf,
                         already_present=same, ok=p.returncode in (0, 3) and nf == 0))
    return all(r['ok'] for r in rows), dict(command='names', binaries=rows)


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
        row('3d decode', 'ok' if gate and len(done) == len(mods) and passed == files else
            ('FAIL' if done else 'not run'),
            f'{len(done)}/{len(mods)} module reports, {passed}/{files} files identical, '
            f'opaque {sum(r["opaque_bytes"] for _, r in done)} bytes; completeness: {comp["ok"]} ok, '
            f'{len(comp["problems"])} problems, {len(comp["unexpected_nested_signatures"])} nested signatures')
    else:
        row('3d decode', 'not run', 'no formats configured')
    for b in proj.binaries():
        nm = b['name']
        idx = jload(os.path.join(b['decompiled'], 'index.json'))
        orph = orphan_line(os.path.join(b['decompiled'], 'recovery.log'))
        cc = jload(os.path.join(b['decompiled'], 'coverage_check.json'))
        mbz = (cc or {}).get('summary', {}).get('must_be_zero')
        if idx is None:
            row(f'3a recover {nm}', 'not run', '')
        else:
            good = orph == 0 and mbz is not None and not any(mbz.values())
            row(f'3a recover {nm}', 'ok' if good else 'FAIL',
                f'{nfunctions(idx)} functions, orphan instructions {orph}, coverage check '
                f'{"clean" if mbz is not None and not any(mbz.values()) else ("not run" if mbz is None else mbz)}')
        fm = jload(os.path.join(b['analysis'], 'features_meta.json'))
        row(f'3b features {nm}', 'ok' if fm else 'not run',
            f'{fm["counts"]["functions"]} functions, {fm["counts"].get("chunks")} chunks' if fm else '')
        nidx = jload(os.path.join(b['named'], 'index.json'))
        apply_ = os.path.join(b['analysis'], 'names_apply.json')
        nf, same = name_failures(os.path.join(b['named'], 'name_failures.txt'))
        if nidx is None:
            row(f'3b names {nm}', 'not run', 'names_apply.json present' if os.path.exists(apply_) else '')
        else:
            napplied = len(jload(apply_) or {}) if os.path.exists(apply_) else 0
            row(f'3b names {nm}', 'ok' if not nf else 'FAIL', f'{napplied} names in names_apply.json, {nf or 0} '
                f'failures' + (f' ({same} already present at their address)' if same else ''))
    order = ['1', '2', '3a', '3b', '3d']
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
    for c in ('recover', 'features', 'names'):
        s = sp.add_parser(c); s.add_argument('--binary')
        if c != 'names':
            s.add_argument('--force', action='store_true')
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
