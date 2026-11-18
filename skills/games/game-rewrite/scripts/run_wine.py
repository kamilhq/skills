#!/usr/bin/env python3
"""Run a Windows program from a fresh copy of the game folder and collect its log (Python stdlib only).
Used for the toolchain's hello programs and for trying a rewrite build by hand.

  python3 -I run_wine.py EXE [--game DIR] [--extra FILE]... [--extra-dir DIR]... [--title TEXT] [--log NAME]
         [--log-out PATH] [--expect TEXT] [--timeout S] [--tries N] [--workdir DIR] [--keep]
         [--runner wine|native] [--project DIR] [-- program args...]

  --game       folder to copy (default: decomp.json rewrite.game, else paths.game, else work/game); never
               modified. The copy goes to a new temporary folder (or --workdir); files are cloned on macOS.
  --extra / --extra-dir   more files to put next to the exe (e.g. the library DLLs of the "dll" flavour)
  --title      wait for an on-screen window with exactly this title (macOS window list, or Windows' own)
  --log        file (relative to the copy) to collect after the run; printed and saved to --log-out
               (default: next to EXE, same name)
  --expect     the run only succeeds if the log contains TEXT
  --timeout    give up after S seconds (default 60); the process is killed
  --tries      start again when a run does not succeed (no window, --expect missing from the log, or a
               non-zero exit without --expect), up to N runs (default 3): Wine on macOS sometimes ends or
               crashes a starting process
  --runner     wine (default on macOS/Linux; env WINE, WINEPREFIX) or native (default on Windows)
Exit 0 when the title was seen (if asked), the process exited by itself and --expect matched.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rwlib  # noqa: E402

PROG = 'run_wine'


def main(argv):
    prog_args = []
    if '--' in argv:
        i = argv.index('--')
        argv, prog_args = argv[:i], argv[i + 1:]
    a = rwlib.parse_args(PROG, __doc__, argv, [
        ('--game', 'str', None), ('--extra', 'list', None), ('--extra-dir', 'list', None), ('--title', 'str', None),
        ('--log', 'str', None), ('--log-out', 'str', None), ('--expect', 'str', None), ('--timeout', 'float', 60.0),
        ('--tries', 'int', 3), ('--workdir', 'str', None), ('--keep', 'flag', False), ('--runner', 'str', None),
        ('--project', 'str', '.')], [('exe', '1')])
    project = a['project']
    cfg, rw = rwlib.load_config(project)
    mode = rwlib.runner_mode(rw, a['runner'])
    game = a['game'] or rwlib.project_path(project, rw.get('game') or rwlib.get(cfg, 'paths.game', 'work/game'))
    exe = os.path.abspath(a['exe'])
    work = os.path.abspath(a['workdir']) if a['workdir'] else tempfile.mkdtemp(prefix='rewrite_wine_')
    env = rwlib.run_env(project, rw, mode)
    ok = good = False
    try:
        rwlib.copy_tree(os.path.abspath(game), work)
        extras = list(a['extra'])
        for d in a['extra_dir']:
            extras += [os.path.join(d, f) for f in sorted(os.listdir(d)) if os.path.isfile(os.path.join(d, f))]
        for f in [exe] + extras:
            rwlib.clone(os.path.abspath(f), os.path.join(work, os.path.basename(f)))
        name = os.path.basename(exe)
        log_path = os.path.join(work, a['log']) if a['log'] else None
        out_path = os.path.join(work, '.run-output.txt')
        have_log, text = False, ''
        for attempt in range(1, max(1, a['tries']) + 1):
            if log_path and os.path.exists(log_path):
                os.remove(log_path)
            t0 = time.time()
            with open(out_path, 'w') as out:
                proc = subprocess.Popen(rwlib.exe_command(mode, name, work, prog_args), cwd=work, env=env,
                                        stdout=out, stderr=subprocess.STDOUT)
            seen = None
            while proc.poll() is None and time.time() - t0 < a['timeout']:
                if a['title'] and seen is None and a['title'] in (rwlib.window_titles() or []):
                    seen = time.time() - t0
                    print('[run_wine] window "%s" on screen after %.1f s' % (a['title'], seen), flush=True)
                time.sleep(0.25)
            timed_out = proc.poll() is None
            if timed_out:
                proc.kill()
                proc.wait()
            rc = proc.returncode
            have_log = bool(log_path and os.path.exists(log_path))
            text = ''
            if have_log:
                with open(log_path, errors='replace') as f:
                    text = f.read()
            print('[run_wine] try %d: exit %s after %.1f s%s' % (attempt, rc, time.time() - t0,
                                                                 ' (timeout, killed)' if timed_out else ''), flush=True)
            with open(out_path, errors='replace') as f:
                crash = [l.strip() for l in f if 'Unhandled' in l or 'page fault' in l]
            for l in crash[:3]:
                print('[run_wine]   wine: %s' % l, flush=True)
            good = (not timed_out and (a['title'] is None or seen is not None)
                    and (a['expect'] in text if a['expect'] else rc == 0))
            if not good and attempt < a['tries']:
                print('[run_wine] run did not succeed (Wine sometimes ends or crashes a starting process): '
                      'starting again', flush=True)
                continue
            break
        if have_log:
            dst = a['log_out'] or os.path.join(os.path.dirname(exe), os.path.basename(a['log']))
            os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
            shutil.copy2(log_path, dst)
            print('[run_wine] log %s (saved to %s):' % (a['log'], dst))
            print(text.rstrip())
        elif a['log']:
            print('[run_wine] no log file %s; program output:' % a['log'])
            with open(out_path, errors='replace') as f:
                print(f.read()[-4000:])
        ok = good
        if a['title'] and rwlib.window_titles() is None:
            print('[run_wine] (window titles cannot be read on this system)')
        print('[run_wine] %s' % ('PASS' if ok else 'FAIL'))
    finally:
        if a['keep']:
            print('[run_wine] kept %s' % work)
        elif not a['workdir']:
            shutil.rmtree(work, ignore_errors=True)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
