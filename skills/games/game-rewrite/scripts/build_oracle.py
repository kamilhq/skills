#!/usr/bin/env python3
"""Build the ORACLE: the original game rebuilt from its matched source plus the test hooks.

  python3 -I build_oracle.py [--project DIR] [--out DIR] [--prepare-only]

Configured by decomp.json rewrite.oracle:
  binary   the decomp.json binaries[].name that gets the hooks (default: the first with "matching": true)
  dir      the oracle's own project folder (default build/oracle)
  files    files to copy into the source copy (the hook code, e.g. a header built on harness/harness_core.h)
  edits    a JSON file (or an inline list) of edits to the copied units:
           [{"unit": "217_main_loop.cpp", "desc": "...", "old": "exact text", "new": "replacement",
             "count": 1}]; every "old" must occur exactly "count" times (default 1), or nothing is built
  exe      the built exe (default <dir>/game/<binary file>); record_oracle.py reads it
Steps (the project's own source folder is never modified):
  1. copy the binary's source (binaries[].src, else <paths.src>/<name>) to <dir>/src/<name>, add "files",
     apply "edits" (line ends kept);
  2. write <dir>/decomp.json: the project's config with every path pointing back to the project, except
     the source of this binary (the copy), reports and build scratch (inside <dir>);
  3. copy the game folder (paths.game) to --out (default <dir>/game) without the binary itself, and run the
     decomp skill's `pipeline.py build --mode source --skip-data --project <dir> --out <out>`: edited
     functions are linked from the copy's C++, everything else as in the source build.
Prints a JSON summary (oracle exe, SHA-256, seconds, the pipeline's summary); exit 0 when the exe was built.
--prepare-only stops after step 2. Python standard library only.
"""
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rwlib  # noqa: E402

PROG = 'build_oracle'
PATH_DEFAULTS = {'game': 'work/game', 'extracted': 'extracted', 'decoded': 'decoded', 'formats': 'tools/formats',
                 'analysis': 'analysis', 'work': 'work', 'manifest': 'manifests/game.json'}
REBASE_BIN = ('decompiled', 'named', 'reassembled', 'analysis', 'ghidra_project', 'src')


class Fail(Exception):
    pass


def rebase(rel, p):
    p2 = os.path.expanduser(p)
    return p if os.path.isabs(p2) else os.path.normpath(os.path.join(rel, p)).replace(os.sep, '/')


def prepare(project, cfg, rw, oracle):
    oc = rw.get('oracle') or {}
    bins = cfg.get('binaries') or []
    name = oc.get('binary') or next((b['name'] for b in bins if b.get('matching')), None)
    binary = next((b for b in bins if b.get('name') == name), None)
    if binary is None:
        raise Fail('no binary %s in decomp.json (rewrite.oracle.binary)' % name)
    paths = cfg.get('paths') or {}
    src_default = paths.get('src', 'src_matched')
    src = rwlib.project_path(project, binary.get('src') or os.path.join(src_default, name))
    if not os.path.isdir(src):
        raise Fail('source folder %s not found' % src)
    dst = os.path.join(oracle, 'src', name)
    if os.path.exists(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    for f in oc.get('files') or []:
        shutil.copy2(rwlib.project_path(project, f), os.path.join(dst, os.path.basename(f)))
    edits = oc.get('edits') or []
    if isinstance(edits, str):
        with open(rwlib.project_path(project, edits), encoding='utf-8') as f:
            edits = json.load(f)
    units = {}
    for e in edits:
        units.setdefault(e['unit'], []).append(e)
    for unit, es in units.items():
        p = os.path.join(dst, unit)
        if not os.path.exists(p):
            raise Fail('edit unit %s not found in %s' % (unit, src))
        with open(p, encoding='utf-8', newline='') as f:
            text = f.read()
        crlf = '\r\n' in text
        text = text.replace('\r\n', '\n')
        for e in es:
            n = text.count(e['old'])
            want = e.get('count', 1)
            if n != want:
                raise Fail('edit "%s" in %s: found %d times, expected %d (source changed?)'
                           % (e.get('desc', e['old'][:40]), unit, n, want))
            text = text.replace(e['old'], e['new'])
        if crlf:
            text = text.replace('\n', '\r\n')
        with open(p, 'w', encoding='utf-8', newline='') as f:
            f.write(text)
    rel = os.path.relpath(os.path.abspath(project), os.path.abspath(oracle))
    new = json.loads(json.dumps(cfg))
    new.pop('rewrite', None)
    np = {}
    for k, v in paths.items():
        np[k] = v if k in ('src', 'reports', 'build') else rebase(rel, v)
    for k, v in PATH_DEFAULTS.items():      # the decomp skill's defaults, pointing back to the project
        if k not in np:
            np[k] = rebase(rel, v)
    np['src'], np['reports'], np['build'] = 'src', 'reports', 'build'
    new['paths'] = np
    for b in new.get('binaries') or []:
        for k in REBASE_BIN:
            if k in b:
                b[k] = rebase(rel, b[k])
        if b.get('name') == name:
            b['src'] = 'src/' + name
        elif 'src' not in b:
            b['src'] = rebase(rel, os.path.join(src_default, b['name']))
    with open(os.path.join(oracle, 'decomp.json'), 'w', encoding='utf-8') as f:
        f.write(rwlib.dumps(new) + '\n')
    return binary, dst, len(edits)


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [('--project', 'str', '.'), ('--out', 'str', None),
                                               ('--prepare-only', 'flag', False)])
    project = a['project']
    cfg, rw = rwlib.load_config(project)
    oc = rw.get('oracle') or {}
    oracle = rwlib.project_path(project, oc.get('dir', 'build/oracle'))
    os.makedirs(oracle, exist_ok=True)
    try:
        binary, dst, nedits = prepare(project, cfg, rw, oracle)
    except Fail as e:
        sys.stderr.write('%s: %s\n' % (PROG, e))
        return 1
    sys.stderr.write('harness source set: %s (%d edits)\n' % (os.path.relpath(dst, project).replace(os.sep, '/'),
                                                              nedits))
    if a['prepare_only']:
        sys.stdout.write(rwlib.dumps({'ok': True, 'prepared': os.path.relpath(oracle, project).replace(os.sep, '/'),
                                      'edits': nedits}) + '\n')
        return 0
    out = os.path.abspath(a['out'] or os.path.join(oracle, 'game'))
    game = rwlib.project_path(project, rwlib.get(cfg, 'paths.game', 'work/game'))
    exe_name = binary['file']
    for r, ds, fs in os.walk(game):
        for f in fs:
            s = os.path.join(r, f)
            relp = os.path.relpath(s, game)
            if relp == exe_name:
                continue
            d = os.path.join(out, relp)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            if not os.path.exists(d) or os.path.getsize(d) != os.path.getsize(s):
                shutil.copy2(s, d)
    exe = os.path.join(out, exe_name)
    if os.path.exists(exe):
        os.remove(exe)
    ds = rwlib.find_decomp_scripts(project, rw)
    if not ds:
        sys.stderr.write('%s: byte-identical-game-decomp scripts not found (DECOMP_SCRIPTS)\n' % PROG)
        return 1
    t0 = time.time()
    c = subprocess.run([sys.executable, '-I', os.path.join(ds, 'pipeline.py'), 'build', '--mode', 'source',
                        '--skip-data', '--project', oracle, '--out', out], cwd=project,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, errors='replace')
    with open(os.path.join(oracle, 'build.log'), 'w') as f:
        f.write(c.stderr)
    try:
        res = json.loads(c.stdout)
    except ValueError:
        res = {'error': 'no JSON from pipeline.py', 'stdout': c.stdout[-2000:]}
    ok = c.returncode == 0 and os.path.exists(exe)
    summary = {'oracle_exe': os.path.relpath(exe, project).replace(os.sep, '/'), 'ok': ok,
               'seconds': round(time.time() - t0), 'pipeline': res,
               'log': os.path.relpath(os.path.join(oracle, 'build.log'), project).replace(os.sep, '/')}
    if ok:
        summary['sha256'] = rwlib.sha256_file(exe)
    sys.stdout.write(rwlib.dumps(summary) + '\n')
    if not ok:
        sys.stderr.write(c.stderr[-4000:])
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
