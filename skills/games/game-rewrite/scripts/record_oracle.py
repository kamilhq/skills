#!/usr/bin/env python3
"""Record the oracle's trace for every scenario and prove it is deterministic.

  python3 -I record_oracle.py [--exe EXE] [--runs N] [--out DIR] [--game DIR] [--tries N] [--settle S]
         [--runner wine|native] [--project DIR] [SCENARIO ...]

Each scenario (default: every *.txt in rewrite.scenarios) runs --runs times (default 2; use 3 or more for the
record) through run_scenario.py. Every run's trace and save folder must be byte-identical to the first run's.
Then the first run's trace is written to <out>/<scenario>.trace and its save files to <out>/<scenario>.saves/,
and <out>/determinism.json records, per scenario and run: frames, tries, seconds per try, SHA-256 of the
trace and of each save file, the comparison with run 1, and the oracle exe's SHA-256. Scenarios that are
not deterministic are not written (their entry says why). --exe defaults to rewrite.oracle.exe, --out to
rewrite.oracle.traces (default: the "oracle" folder next to the scenarios folder).
Prints a JSON summary {scenario: {deterministic, frames}}; exit 0 when every scenario is deterministic.
Python standard library only.
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import compare_traces  # noqa: E402
import rwlib  # noqa: E402

PROG = 'record_oracle'


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [
        ('--exe', 'str', None), ('--runs', 'int', 2), ('--out', 'str', None), ('--game', 'str', None),
        ('--tries', 'int', None), ('--settle', 'str', None), ('--runner', 'str', None), ('--project', 'str', '.')],
        [('scenarios', '*')])
    project = a['project']
    _, rw = rwlib.load_config(project)
    exe = a['exe'] or rwlib.project_path(project, rwlib.get(rw, 'oracle.exe'))
    if not exe or not os.path.isfile(exe):
        sys.stdout.write(rwlib.dumps({'error': 'no oracle exe (--exe or rewrite.oracle.exe): %s' % exe}) + '\n')
        return 2
    scen_dir = rwlib.project_path(project, rw.get('scenarios', 'rewrite/harness/scenarios'))
    scen = a['scenarios'] or sorted(glob.glob(os.path.join(scen_dir, '*.txt')))
    if not scen:
        sys.stdout.write(rwlib.dumps({'error': 'no scenarios in %s' % scen_dir}) + '\n')
        return 2
    outdir = a['out'] or rwlib.project_path(project, rwlib.get(rw, 'oracle.traces')) or \
        os.path.join(os.path.dirname(scen_dir), 'oracle')
    os.makedirs(outdir, exist_ok=True)
    rep_path = os.path.join(outdir, 'determinism.json')
    report = {}
    if os.path.exists(rep_path):
        with open(rep_path, encoding='utf-8') as f:
            report = json.load(f)
    report['exe_sha256'] = rwlib.sha256_file(exe)
    report.setdefault('scenarios', {})
    passthru = ['--project', project]
    for k in ('game', 'tries', 'settle', 'runner'):
        if a[k] is not None:
            passthru += ['--' + k, str(a[k])]
    all_ok = True
    tmp = tempfile.mkdtemp(prefix='rewrite_record_')
    try:
        for s in scen:
            name = os.path.splitext(os.path.basename(s))[0]
            runs = []
            for r in range(a['runs']):
                tr = os.path.join(tmp, '%s.%d.trace' % (name, r))
                sv = os.path.join(tmp, '%s.%d.saves' % (name, r))
                c = subprocess.run([sys.executable, '-I', os.path.join(HERE, 'run_scenario.py'), '--exe', exe,
                                    '--scenario', s, '--out', tr, '--saves-out', sv] + passthru,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                try:
                    res = json.loads(c.stdout)
                except ValueError:
                    res = {'ok': False}
                row = {'ok': bool(res.get('ok')), 'tries': len(res.get('tries') or []),
                       'seconds': [t.get('seconds') for t in res.get('tries') or []]}
                if row['ok']:
                    row['frames'] = len(compare_traces.parse(tr)[1])
                    row['trace_sha256'] = rwlib.sha256_file(tr)
                    row['saves'] = {f: rwlib.sha256_file(os.path.join(sv, f)) for f in sorted(os.listdir(sv))} \
                        if os.path.isdir(sv) else {}
                else:
                    row['error'] = res.get('error') or (c.stderr or '')[-500:]
                runs.append(row)
                sys.stderr.write('%s run %d: %s\n' % (name, r + 1, 'ok, %d frames' % row['frames']
                                                      if row['ok'] else 'FAILED'))
                sys.stderr.flush()
            ok = all(x['ok'] for x in runs)
            det = None
            if ok:
                ref = os.path.join(tmp, '%s.0.trace' % name)
                det = []
                for r in range(1, a['runs']):
                    summ = compare_traces.compare(ref, os.path.join(tmp, '%s.%d.trace' % (name, r)))[0]
                    det.append({'run': r + 1, 'identical': summ['identical'],
                                'first_diff_frame': summ['first_diff_frame'],
                                'same_saves': runs[r]['saves'] == runs[0]['saves']})
                ok = all(d['identical'] and d['same_saves'] for d in det) and \
                    len({x['trace_sha256'] for x in runs}) == 1
                if ok:
                    shutil.copy2(ref, os.path.join(outdir, '%s.trace' % name))
                    sd = os.path.join(outdir, '%s.saves' % name)
                    if os.path.exists(sd):
                        shutil.rmtree(sd)
                    if os.path.isdir(os.path.join(tmp, '%s.0.saves' % name)):
                        shutil.copytree(os.path.join(tmp, '%s.0.saves' % name), sd)
            rel = os.path.relpath(os.path.abspath(s), os.path.abspath(project)).replace(os.sep, '/')
            report['scenarios'][name] = {'scenario': rel, 'runs': runs, 'compared': det, 'deterministic': ok,
                                         'recorded': time.strftime('%Y-%m-%dT%H:%M:%S')}
            all_ok = all_ok and ok
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    with open(rep_path, 'w', encoding='utf-8') as f:
        f.write(rwlib.dumps(report) + '\n')
    sys.stdout.write(rwlib.dumps({k: {'deterministic': v['deterministic'],
                                      'frames': [r.get('frames') for r in v['runs']]}
                                  for k, v in report['scenarios'].items()}) + '\n')
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
