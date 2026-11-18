#!/usr/bin/env node
// Port of ../run_scenario.py (same command line, output and exit codes). Node built-ins only.
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import * as L from './lib/rwlib.mjs'

const PROG = 'run_scenario'
const DOC = "Run one scenario (a replay file) with a game exe and collect its per-frame trace and save files.\n\n  python3 -I run_scenario.py --exe EXE --scenario FILE --out TRACE [--game DIR] [--exit-frame N]\n         [--timeout S] [--stall S] [--tries N] [--settle S] [--saves-out DIR] [--no-fb] [--keep]\n         [--arg A]... [--env K=V]... [--runner wine|native] [--project DIR]\n\nThe exe is the oracle or a rewrite; both implement the same hooks (references/harness.md). The game folder\n(--game, else decomp.json rewrite.game, else the exe's folder) is copied to a scratch folder and the exe is\nput into the copy under the name rewrite.exe_name (default: the exe's own name), so the original folder is\nnever written to. The program runs with:\n  env  rewrite.env.replay = the replay file, rewrite.env.trace = the trace file to write,\n       rewrite.env.exit_frame = N (quit after the line of frame N), rewrite.env.fb = \"0\" with --no-fb,\n       rewrite.extra_env, --env K=V\n  args rewrite.args then --arg values; \"{basedir}\" in them becomes an empty scratch folder (settings and\n       saves start from defaults and never touch the user's), \"{game}\" the scratch game folder.\nPaths given to the program are Wine paths (Z:\\...) under --runner wine (default on macOS/Linux), host\npaths under native (default on Windows). The exit frame comes from --exit-frame or a \"#! exit_frame=N\" line\nof the scenario. A try counts when the trace has the header (rewrite.trace.header, if set) and a line for\nevery frame 0..N. Otherwise it is tried again (Wine sometimes ends or hangs a starting process): a try is\nabandoned after --timeout seconds (default 60 + 4x the scenario's real-time length at rewrite.fps, default\n30) or when the trace has not grown for --stall seconds (default 30). --saves-out copies the save folder\n(basedir/<rewrite.saves>, default the whole basedir) after a good run.\nPrints a JSON summary; exit 0 on success. Env: WINE, WINESERVER, WINEPREFIX. Python standard library only."
const DEFAULT_ENV = { replay: 'GAME_REPLAY', trace: 'GAME_TRACE', exit_frame: 'GAME_EXIT_FRAME', fb: 'GAME_TRACE_FB' }

async function runOnce (ctx, exitFrame) {
  const { trace, basedir } = ctx
  if (fs.existsSync(trace)) fs.rmSync(trace)
  if (fs.existsSync(basedir)) L.rmtree(basedir)
  L.makedirs(basedir)
  L.wineserverKill(ctx.mode, ctx.env)
  await L.sleep(ctx.settle * 1000)
  const t0 = Date.now()
  const p = spawn(ctx.cmd[0], ctx.cmd.slice(1), { cwd: ctx.exe_dir, env: ctx.env, stdio: 'ignore' })
  let rc = null; let exited = false
  const done = new Promise(resolve => {
    p.on('exit', (code, sig) => { exited = true; rc = code !== null ? code : -(L.signalNumber(sig)); resolve() })
    p.on('error', () => { exited = true; rc = null; resolve() })
  })
  let timedOut = false; let stalled = false; let lastSize = -1; let lastChange = Date.now()
  for (;;) {
    await Promise.race([done, L.sleep(250)])
    if (exited) break
    const now = Date.now()
    const size = fs.existsSync(trace) ? fs.statSync(trace).size : -1
    if (size !== lastSize) { lastSize = size; lastChange = now }
    if ((now - t0) / 1000 > ctx.timeout) { timedOut = true; break }
    if ((now - lastChange) / 1000 > ctx.stall) { stalled = true; break }
  }
  if (!timedOut && !stalled && fs.existsSync(trace)) {
    for (let i = 0; i < 20; i++) {
      if (L.traceFrames(trace, ctx.header, ctx.ff)[2] >= exitFrame) break
      await L.sleep(500)
    }
  }
  L.wineserverKill(ctx.mode, ctx.env)
  if (!exited) {
    p.kill('SIGKILL')
    await done
    if (timedOut || stalled) rc = null
  }
  const [ok, n, last] = L.traceFrames(trace, ctx.header, ctx.ff)
  return new Map([['rc', rc], ['timed_out', timedOut], ['stalled', stalled], ['seconds', L.round1((Date.now() - t0) / 1000)],
    ['header', ok], ['lines', n], ['last_frame', last], ['complete', ok && last === exitFrame && n === exitFrame + 1]])
}

export async function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [
    ['--exe', 'str', L.REQUIRED], ['--scenario', 'str', L.REQUIRED], ['--out', 'str', L.REQUIRED],
    ['--game', 'str', null], ['--exit-frame', 'int', null], ['--timeout', 'float', null],
    ['--stall', 'float', new L.PyFloat(30)], ['--tries', 'int', 5], ['--settle', 'float', new L.PyFloat(1)],
    ['--saves-out', 'str', null], ['--no-fb', 'flag', false], ['--keep', 'flag', false], ['--arg', 'list', null],
    ['--env', 'list', null], ['--runner', 'str', null], ['--project', 'str', '.']])
  const project = a.project
  const rw = L.loadConfig(project)[1]
  const mode = L.runnerMode(rw, a.runner)
  const native = mode === 'native'
  const exe = L.abspath(a.exe)
  const game = L.abspath(a.game || L.projectPath(project, rw.game) || L.dirname(exe))
  const meta = L.scenarioMeta(a.scenario)
  const exitFrame = a.exit_frame !== null ? a.exit_frame : parseInt(meta.exit_frame !== undefined ? meta.exit_frame : '-1', 10)
  if (!(exitFrame >= 0)) {
    process.stdout.write(L.dumps(new Map([['ok', false], ['error', 'no exit frame (--exit-frame or "#! exit_frame=N" in the scenario)']])) + '\n')
    return 2
  }
  const fps = L.num(rw.fps !== undefined ? rw.fps : 30)
  const timeout = (a.timeout !== null && L.num(a.timeout)) || (60 + exitFrame / fps * 4)
  const names = Object.assign({}, DEFAULT_ENV, rw.env || {})
  const exeName = rw.exe_name || L.basename(exe)

  const scratch = L.mkdtemp('rewrite_run_')
  const exeDir = L.join(scratch, 'game')
  L.copyTree(game, exeDir, ['.trace'])
  L.copy2(exe, L.join(exeDir, exeName))
  const scen = L.join(scratch, 'scenario.txt')
  L.copy2(a.scenario, scen)
  const trace = L.join(scratch, 'trace.txt')
  const basedir = L.join(scratch, 'basedir')

  const env = L.runEnv(project, rw, mode)
  for (const k of Object.values(names)) delete env[k]
  env[names.replay] = L.winpath(scen, native)
  env[names.trace] = L.winpath(trace, native)
  env[names.exit_frame] = String(exitFrame)
  if (a.no_fb) env[names.fb] = '0'
  for (const kv of a.env) {
    const i = kv.indexOf('=')
    if (i < 0) env[kv] = ''
    else env[kv.slice(0, i)] = kv.slice(i + 1)
  }
  const subst = [['{basedir}', L.winpath(basedir, native)], ['{game}', L.winpath(exeDir, native)]]
  const args = [...(rw.args || []), ...a.arg].map(x => { for (const [k, v] of subst) x = x.replaceAll(k, v); return x })
  const ctx = {
    mode, env, exe_dir: exeDir, trace, basedir, cmd: L.exeCommand(mode, exeName, exeDir, args), timeout,
    stall: L.num(a.stall), settle: L.num(a.settle), header: L.get(rw, 'trace.header'), ff: L.get(rw, 'trace.frame_field', 'f')
  }
  const tries = []
  let res = null
  for (let t = 0; t < Math.max(1, a.tries); t++) {
    res = await runOnce(ctx, exitFrame)
    tries.push(res)
    if (res.get('complete')) break
  }
  const ok = Boolean(res && res.get('complete'))
  let saves = null
  if (ok) {
    L.makedirs(L.dirname(L.abspath(a.out)))
    L.copy2(trace, a.out)
    if (a.saves_out) {
      const sub = rw.saves !== undefined ? rw.saves : ''
      const sv = sub ? L.join(basedir, sub) : basedir
      L.makedirs(a.saves_out)
      saves = []
      if (L.isdir(sv)) {
        for (const f of L.listdirSorted(sv)) {
          if (L.isfile(L.join(sv, f))) { L.copy2(L.join(sv, f), L.join(a.saves_out, f)); saves.push(f) }
        }
      }
    }
  }
  const out = new Map([['ok', ok], ['exe', a.exe], ['scenario', a.scenario], ['exit_frame', exitFrame],
    ['trace', ok ? a.out : null], ['saves', saves], ['tries', tries], ['scratch', a.keep ? scratch : null]])
  if (!a.keep) L.rmtree(scratch)
  process.stdout.write(L.dumps(out) + '\n')
  return ok ? 0 : 1
}

if (L.isMain(import.meta.url)) process.exitCode = await main(process.argv.slice(2))
