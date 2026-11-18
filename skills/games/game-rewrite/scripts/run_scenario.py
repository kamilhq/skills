#!/usr/bin/env python3
"""Run one scenario (a replay file) with a game exe and collect its per-frame trace and save files.

  python3 -I run_scenario.py --exe EXE --scenario FILE --out TRACE [--game DIR] [--exit-frame N]
         [--timeout S] [--stall S] [--tries N] [--settle S] [--saves-out DIR] [--no-fb] [--keep]
         [--arg A]... [--env K=V]... [--runner wine|native] [--project DIR]

The exe is the oracle or a rewrite; both implement the same hooks (references/harness.md). The game folder
(--game, else decomp.json rewrite.game, else the exe's folder) is copied to a scratch folder and the exe is
put into the copy under the name rewrite.exe_name (default: the exe's own name), so the original folder is
never written to. The program runs with:
  env  rewrite.env.replay = the replay file, rewrite.env.trace = the trace file to write,
       rewrite.env.exit_frame = N (quit after the line of frame N), rewrite.env.fb = "0" with --no-fb,
       rewrite.extra_env, --env K=V
  args rewrite.args then --arg values; "{basedir}" in them becomes an empty scratch folder (settings and
       saves start from defaults and never touch the user's), "{game}" the scratch game folder.
Paths given to the program are Wine paths (Z:\\...) under --runner wine (default on macOS/Linux), host
paths under native (default on Windows). The exit frame comes from --exit-frame or a "#! exit_frame=N" line
of the scenario. A try counts when the trace has the header (rewrite.trace.header, if set) and a line for
every frame 0..N. Otherwise it is tried again (Wine sometimes ends or hangs a starting process): a try is
abandoned after --timeout seconds (default 60 + 4x the scenario's real-time length at rewrite.fps, default
30) or when the trace has not grown for --stall seconds (default 30). --saves-out copies the save folder
(basedir/<rewrite.saves>, default the whole basedir) after a good run.
Prints a JSON summary; exit 0 on success. Env: WINE, WINESERVER, WINEPREFIX. Python standard library only.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rwlib  # noqa: E402

PROG = 'run_scenario'
DEFAULT_ENV = {'replay': 'GAME_REPLAY', 'trace': 'GAME_TRACE', 'exit_frame': 'GAME_EXIT_FRAME', 'fb': 'GAME_TRACE_FB'}


def run_once(ctx, exit_frame):
    trace, basedir = ctx['trace'], ctx['basedir']
    if os.path.exists(trace):
        os.remove(trace)
    if os.path.exists(basedir):
        shutil.rmtree(basedir)
    os.makedirs(basedir)
    rwlib.wineserver_kill(ctx['mode'], ctx['env'])
    time.sleep(ctx['settle'])
    t0 = time.time()
    p = subprocess.Popen(ctx['cmd'], cwd=ctx['exe_dir'], env=ctx['env'], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    timed_out = stalled = False
    rc, last_size, last_change = None, -1, time.time()
    while True:
        try:
            rc = p.wait(timeout=0.25)
            break
        except subprocess.TimeoutExpired:
            pass
        now = time.time()
        size = os.path.getsize(trace) if os.path.exists(trace) else -1
        if size != last_size:
            last_size, last_change = size, now
        if now - t0 > ctx['timeout']:
            timed_out = True
            break
        if now - last_change > ctx['stall']:
            stalled = True
            break
    if not timed_out and not stalled and os.path.exists(trace):
        # the game may still be writing the last line while it shuts down
        for _ in range(20):
            if rwlib.trace_frames(trace, ctx['header'], ctx['ff'])[2] >= exit_frame:
                break
            time.sleep(0.5)
    rwlib.wineserver_kill(ctx['mode'], ctx['env'])
    if p.poll() is None:
        p.kill()
        p.wait()
    ok, n, last = rwlib.trace_frames(trace, ctx['header'], ctx['ff'])
    return {'rc': rc, 'timed_out': timed_out, 'stalled': stalled, 'seconds': round(time.time() - t0, 1),
            'header': ok, 'lines': n, 'last_frame': last,
            'complete': ok and last == exit_frame and n == exit_frame + 1}


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [
        ('--exe', 'str', rwlib.REQUIRED), ('--scenario', 'str', rwlib.REQUIRED), ('--out', 'str', rwlib.REQUIRED),
        ('--game', 'str', None), ('--exit-frame', 'int', None), ('--timeout', 'float', None),
        ('--stall', 'float', 30.0), ('--tries', 'int', 5), ('--settle', 'float', 1.0), ('--saves-out', 'str', None),
        ('--no-fb', 'flag', False), ('--keep', 'flag', False), ('--arg', 'list', None), ('--env', 'list', None),
        ('--runner', 'str', None), ('--project', 'str', '.')])
    project = a['project']
    _, rw = rwlib.load_config(project)
    mode = rwlib.runner_mode(rw, a['runner'])
    native = mode == 'native'
    exe = os.path.abspath(a['exe'])
    game = os.path.abspath(a['game'] or rwlib.project_path(project, rw.get('game')) or os.path.dirname(exe))
    meta = rwlib.scenario_meta(a['scenario'])
    exit_frame = a['exit_frame'] if a['exit_frame'] is not None else int(meta.get('exit_frame', -1))
    if exit_frame < 0:
        sys.stdout.write(rwlib.dumps({'ok': False, 'error': 'no exit frame (--exit-frame or "#! exit_frame=N" '
                                                            'in the scenario)'}) + '\n')
        return 2
    fps = rw.get('fps', 30)
    timeout = a['timeout'] or (60 + exit_frame / float(fps) * 4)
    names = dict(DEFAULT_ENV, **(rw.get('env') or {}))
    exe_name = rw.get('exe_name') or os.path.basename(exe)

    scratch = tempfile.mkdtemp(prefix='rewrite_run_')
    exe_dir = os.path.join(scratch, 'game')
    rwlib.copy_tree(game, exe_dir, skip_ext=('.trace',))
    shutil.copy2(exe, os.path.join(exe_dir, exe_name))
    scen = os.path.join(scratch, 'scenario.txt')
    shutil.copy2(a['scenario'], scen)
    trace = os.path.join(scratch, 'trace.txt')
    basedir = os.path.join(scratch, 'basedir')

    env = rwlib.run_env(project, rw, mode)
    for k in list(names.values()):
        env.pop(k, None)
    env[names['replay']] = rwlib.winpath(scen, native)
    env[names['trace']] = rwlib.winpath(trace, native)
    env[names['exit_frame']] = str(exit_frame)
    if a['no_fb']:
        env[names['fb']] = '0'
    for kv in a['env']:
        k, _, v = kv.partition('=')
        env[k] = v
    subst = {'{basedir}': rwlib.winpath(basedir, native), '{game}': rwlib.winpath(exe_dir, native)}
    args = []
    for x in list(rw.get('args') or []) + a['arg']:
        for k, v in subst.items():
            x = x.replace(k, v)
        args.append(x)
    ctx = {'mode': mode, 'env': env, 'exe_dir': exe_dir, 'trace': trace, 'basedir': basedir,
           'cmd': rwlib.exe_command(mode, exe_name, exe_dir, args), 'timeout': timeout, 'stall': a['stall'],
           'settle': a['settle'], 'header': rwlib.get(rw, 'trace.header'),
           'ff': rwlib.get(rw, 'trace.frame_field', 'f')}
    tries = []
    res = None
    for _ in range(max(1, a['tries'])):
        res = run_once(ctx, exit_frame)
        tries.append(res)
        if res['complete']:
            break
    ok = bool(res and res['complete'])
    saves = None
    if ok:
        out_dir = os.path.dirname(os.path.abspath(a['out']))
        os.makedirs(out_dir, exist_ok=True)
        shutil.copy2(trace, a['out'])
        if a['saves_out']:
            sub = rw.get('saves', '')
            sv = os.path.join(basedir, sub) if sub else basedir
            os.makedirs(a['saves_out'], exist_ok=True)
            saves = []
            if os.path.isdir(sv):
                for f in sorted(os.listdir(sv)):
                    if os.path.isfile(os.path.join(sv, f)):
                        shutil.copy2(os.path.join(sv, f), os.path.join(a['saves_out'], f))
                        saves.append(f)
    out = {'ok': ok, 'exe': a['exe'], 'scenario': a['scenario'], 'exit_frame': exit_frame,
           'trace': a['out'] if ok else None, 'saves': saves, 'tries': tries,
           'scratch': scratch if a['keep'] else None}
    if not a['keep']:
        shutil.rmtree(scratch, ignore_errors=True)
    sys.stdout.write(rwlib.dumps(out) + '\n')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
